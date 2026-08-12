defmodule Ctrld.Channel.Ingest.Telemetry do
  @moduledoc """
  The ingest that reads a recording and writes what it says into ClickHouse.

  It is the seam's deployed implementation: ring bytes come in, a decoder turns
  them into records, and each record a `flow_events` row is made of becomes
  one. Nothing about the decode happens here — a decoder is stateful, the seam
  is not, and the state lives in one process per appliance and ring under this
  module's supervisor. What happens here is the handover, and it is a cast, so
  the connection's own process pays a message send and never a decode.

  ## Which ring becomes rows

  The **log** ring, and not the capture. `flow_events` has no column naming a
  ring, so a table fed from both would answer a question about one appliance's
  flows with two different kinds of thing mixed together and no way to tell
  them apart. They are genuinely different: the log ring holds one record per
  lifecycle or policy event — a flow opened, advanced, closed, refused, revoked
  — which is what a table of flow events means, while the capture holds one
  record per frame the dataplane decided on, orders of magnitude more of them
  and almost all carrying no event at all. The sort key says the same thing
  from the other side: it leads with the instant and the flow slot, which
  separates the log ring's records and collides for the capture's.

  The capture ring is still decoded, and its records counted. That is the
  measurement which makes this choice visible rather than silent — how much
  arrived on each ring against how much was stored — and it is also what
  notices a capture ring that has stopped parsing, which no counter of bytes
  can.

  ## What it never puts anywhere

  A byte of a recording. The rows carry the appliance's own verdict and the
  addresses and ports of the traffic it decided on, which is what the telemetry
  schema exists to hold; the log lines and the telemetry events below carry
  counts, positions and named reasons, and no payload.
  """

  require Logger

  alias Ctrld.Channel.Frame
  alias Ctrld.Channel.Ingest.Telemetry.Ring

  @behaviour Ctrld.Channel.Ingest

  @registry __MODULE__.Registry
  @supervisor __MODULE__.Supervisor

  @storing_ring :log

  @doc """
  The processes this ingest needs, for the application's own supervisor.

  A registry so a shipment finds the ring it belongs to, and a dynamic
  supervisor so a ring that has never been heard from is started by the first
  shipment rather than by a list of appliances someone has to keep.
  """
  @spec children() :: [Supervisor.child_spec() | {module(), term()}]
  def children do
    [
      {Registry, keys: :unique, name: @registry},
      {DynamicSupervisor, strategy: :one_for_one, name: @supervisor}
    ]
  end

  @doc "The ring whose records become `flow_events` rows."
  @spec storing_ring() :: Frame.ring()
  def storing_ring, do: @storing_ring

  @doc false
  @spec name(String.t(), Frame.ring()) :: {:via, module(), term()}
  def name(device_id, ring), do: {:via, Registry, {@registry, {device_id, ring}}}

  @doc """
  The telemetry events this ingest emits, by the name that ends each one.

  Every one carries `:device_id` and `:ring` in its metadata, so a count is
  always attributable to one appliance's one ring.
  """
  @spec events() :: [[atom()]]
  def events do
    Enum.map(
      ~w(rows_built rows_inserted insert_failed rows_dropped records_skipped samples_skipped
         frame_unread decoder_refused resynchronised bytes_lost)a,
      &(prefix() ++ [&1])
    )
  end

  @doc "What every event this ingest emits is named under."
  @spec prefix() :: [atom()]
  def prefix, do: [:ctrld, :channel, :ingest, :telemetry]

  @doc false
  @spec emit(atom(), map(), map()) :: :ok
  def emit(name, measurements, metadata),
    do: :telemetry.execute(prefix() ++ [name], measurements, metadata)

  @impl Ctrld.Channel.Ingest
  @spec ring_bytes(String.t(), Frame.ring(), non_neg_integer(), binary()) :: :ok
  def ring_bytes(device_id, ring, position, bytes)
      when is_binary(device_id) and ring in [:log, :capture] and is_integer(position) and
             is_binary(bytes) do
    case ring_process(device_id, ring) do
      {:ok, pid} -> GenServer.cast(pid, {:bytes, self(), position, bytes})
      # The seam's return is `:ok` and nothing else, so a ring that will not
      # start is not something to refuse the shipment over. It is counted where
      # a refusal would have been read, and the bytes are lost — which the
      # appliance's own resume from an unadvanced cursor is what recovers.
      {:error, reason} -> lost(device_id, ring, bytes, reason)
    end

    :ok
  end

  @doc """
  Write out what a ring is holding, and say how that went.

  Synchronous, and the answer is the store's: it is how a caller that must know
  the rows have landed — the suite, and a shutdown that wants what is held —
  finds out rather than waiting on the age bound. A ring nothing has shipped to
  has nothing to write and says so.
  """
  @spec flush(String.t(), Frame.ring()) :: :ok | {:error, term()}
  def flush(device_id, ring) do
    case Registry.lookup(@registry, {device_id, ring}) do
      [{pid, _value}] -> GenServer.call(pid, :flush)
      [] -> :ok
    end
  end

  @spec ring_process(String.t(), Frame.ring()) :: {:ok, pid()} | {:error, term()}
  defp ring_process(device_id, ring) do
    case Registry.lookup(@registry, {device_id, ring}) do
      [{pid, _value}] ->
        {:ok, pid}

      [] ->
        # Two shipments for one ring can reach this at once, and exactly one of
        # them starts it: the registry's name is what settles that, and the
        # loser is told which process won rather than having to look again.
        case DynamicSupervisor.start_child(@supervisor, {Ring, {device_id, ring}}) do
          {:ok, pid} -> {:ok, pid}
          {:error, {:already_started, pid}} -> {:ok, pid}
          {:error, reason} -> {:error, reason}
        end
    end
  end

  @spec lost(String.t(), Frame.ring(), binary(), term()) :: :ok
  defp lost(device_id, ring, bytes, reason) do
    emit(:bytes_lost, %{bytes: byte_size(bytes)}, %{
      device_id: device_id,
      ring: ring,
      cause: :no_ring_process
    })

    Logger.error(
      "ctrld: appliance #{device_id} #{ring} ring has no ingest process: #{inspect(reason)}"
    )
  end
end
