defmodule Ctrld.Channel.Ingest.Telemetry.Ring do
  @moduledoc """
  One appliance's one ring, being decoded into telemetry rows.

  A decoder is stateful and the ingest seam is not — the seam hands over a
  device, a ring, a position and a run of bytes, and holds nothing between
  calls — so the state a `Ctrld.Pcapng` decoder needs lives here, one process
  per appliance and ring. The seam casts to it and returns, which is what keeps
  the connection's own process out of a decode.

  ## Lifetime

  A process lives as long as the session feeding it. The first shipment names
  the connection that delivered it, this process monitors it, and its going
  away flushes what is held and ends the process — so nothing is left behind by
  an appliance that disconnected, and nothing outlives the state's own
  validity: a half-arrived block belongs to the stream it arrived on, and that
  stream is over.

  A shipment from a different connection than the one being watched is a
  reconnect that overtook the notice of the old one. The watch moves to the new
  connection, and the position guard below treats the stream as having jumped,
  which it has.

  ## The position guard

  `position` is the ring's own absolute append coordinate and the appliance
  chooses it. A shipment that does not begin where the last one ended means the
  stream jumped — a ring the traffic wrapped past, a reader that moved, an
  appliance that restarted mid-stream — and feeding those bytes to a decoder
  holding the tail of a block that is no longer adjacent to them would decode
  the join as a block and answer plausible numbers for it. So the decoder is
  discarded instead and the stream is picked up at the next section header,
  which is the only offset in a pcapng stream a reader can start from knowing
  what it is looking at. What lies between is counted as lost, because it is.

  The seam cannot refuse a shipment — the bytes are already on this side of the
  wire and the appliance is owed no answer — so a jump is logged, counted, and
  recovered from rather than raised.

  ## Where the durable cursor is applied

  Bytes at or below the cursor are bytes whose rows are already in ClickHouse,
  and they must not become rows a second time. They are still *fed* to the
  decoder, because a pcapng stream is only readable from its section header and
  a record's instant is resolved against an interface table built near it —
  skipping the bytes outright would leave nothing able to read the ones after
  them. What is skipped is the row: a run fed from at or below the cursor
  produces none.

  That split is exact rather than approximate, because the cursor is only ever
  set to the end of a whole block. A run is therefore cut at the cursor and fed
  as two, and no block ever straddles the join.
  """

  # Temporary, because there is nothing to restart into. Everything this process
  # holds — the decoder's half-arrived block, where the stream had reached — is
  # the property of one session, so a replacement started in its place would
  # hold none of it and would differ in no way from the one the next shipment
  # starts anyway. It also keeps one ring's failure to one ring: a supervisor
  # that restarted these would, given a store or a database that is down for
  # long enough, exhaust its restart intensity and take the server with it.
  use GenServer, restart: :temporary

  require Logger

  alias Ctrld.Channel.Frame
  alias Ctrld.Channel.Ingest.Telemetry, as: Ingest
  alias Ctrld.Pcapng
  alias Ctrld.Pcapng.{Custom, Packet}
  alias Ctrld.Telemetry.{Cursor, FlowEvent, MetricSnapshot, Store}

  # The pcapng section header, as it lies on the wire in either byte order —
  # the writer's magic is a palindrome, which is what lets a section be found
  # before the order it declares has been read. Finding it is how a stream that
  # jumped is picked up again.
  @section_header <<0x0A, 0x0D, 0x0D, 0x0A>>

  # What a resynchronising reader keeps between shipments: enough that a section
  # header split across two of them is still found, and no more. Three bytes,
  # because a four-byte marker cut anywhere leaves at most three behind.
  @resync_tail 3

  # The two bounds a batch is flushed on. Rows are worth batching because one
  # insert is one HTTP round trip, and worth flushing on age because a quiet
  # appliance's last few records should not wait for a five-hundredth that may
  # be hours away.
  @batch_rows 500
  @batch_age 2_000

  # How many rows may be held while the store is refusing them. A failed insert
  # keeps its rows and retries them with the next batch, which is what makes a
  # store that restarted cost nothing; this is where that stops being free and
  # the oldest are dropped, counted, and named in the log.
  @max_pending 5_000

  # The two tables a recording's blocks become. One list per table rather than
  # one list of tagged rows, because a batch is inserted per table and the
  # cursor may only move once every table's batch is in.
  @tables ["flow_events", "metric_samples"]

  @typep state :: %{
           device_id: String.t(),
           ring: Frame.ring(),
           cursor: non_neg_integer(),
           decoder: nil | Pcapng.t(),
           fed_through: nil | non_neg_integer(),
           resync: nil | {non_neg_integer(), binary()},
           pending: %{String.t() => [map()]},
           pending_through: nil | non_neg_integer(),
           session: nil | pid(),
           monitor: nil | reference(),
           timer: nil | reference(),
           failing?: boolean()
         }

  @doc "The batch size a flush happens at."
  @spec batch_rows() :: pos_integer()
  def batch_rows, do: @batch_rows

  @doc "How long a partial batch waits, in milliseconds."
  @spec batch_age() :: pos_integer()
  def batch_age, do: @batch_age

  @doc false
  @spec start_link({String.t(), Frame.ring()}) :: GenServer.on_start()
  def start_link({device_id, ring}) do
    GenServer.start_link(__MODULE__, {device_id, ring}, name: Ingest.name(device_id, ring))
  end

  @impl GenServer
  def init({device_id, ring}) do
    # The cursor is a database read, and this runs while the connection's own
    # process waits for the child to start. It is deferred to a continuation,
    # which runs before any shipment in the mailbox, so the read is off that
    # process's path and still ahead of the first byte it hands over.
    {:ok,
     %{
       device_id: device_id,
       ring: ring,
       cursor: 0,
       decoder: nil,
       fed_through: nil,
       resync: nil,
       pending: empty(),
       pending_through: nil,
       session: nil,
       monitor: nil,
       timer: nil,
       failing?: false
     }, {:continue, :cursor}}
  end

  @impl GenServer
  def handle_continue(:cursor, state) do
    {:noreply, %{state | cursor: cursor(state)}}
  end

  @impl GenServer
  def handle_cast({:bytes, session, position, bytes}, state) do
    {:noreply, state |> watch(session) |> arrived(position, bytes)}
  end

  @impl GenServer
  def handle_call(:flush, _from, state) do
    {result, state} = flush(state)
    {:reply, result, state}
  end

  @impl GenServer
  def handle_info(:flush, state) do
    {_result, state} = flush(state)
    {:noreply, state}
  end

  # The session that was feeding this ring is gone. What is held is worth
  # writing — the rows are already decoded and the store is reachable — and
  # what is half-arrived is not, its stream being over.
  def handle_info({:DOWN, monitor, :process, _pid, _reason}, %{monitor: monitor} = state) do
    {_result, state} = flush(state)
    {:stop, :normal, state}
  end

  def handle_info(_message, state), do: {:noreply, state}

  # Which connection is feeding this ring. A shipment from another one is a
  # reconnect, and the old connection's notice has not arrived yet or never
  # will; either way what it was streaming is over.
  @spec watch(state(), pid()) :: state()
  defp watch(%{session: session} = state, session), do: state

  defp watch(state, session) do
    if state.monitor, do: Process.demonitor(state.monitor, [:flush])
    %{state | session: session, monitor: Process.monitor(session)}
  end

  @spec arrived(state(), non_neg_integer(), binary()) :: state()
  defp arrived(state, position, bytes) do
    cond do
      state.fed_through == position and state.decoder != nil ->
        feed(state, position, bytes)

      state.fed_through == nil and state.decoder == nil and state.resync == nil ->
        # The first shipment of a stream. There is no decoder to have jumped
        # away from, so this is not a gap: the stream is simply picked up at
        # the section header it is expected to open on.
        state |> resynchronising(position) |> resynchronise(position, bytes)

      state.decoder == nil ->
        resynchronise(state, position, bytes)

      true ->
        jumped(state, position, bytes)
    end
  end

  @spec jumped(state(), non_neg_integer(), binary()) :: state()
  defp jumped(state, position, bytes) do
    Logger.warning(
      "ctrld: appliance #{state.device_id} #{state.ring} ring jumped from position " <>
        "#{state.fed_through} to #{position}; resynchronising at the next section"
    )

    Ingest.emit(:resynchronised, %{count: 1}, %{
      device_id: state.device_id,
      ring: state.ring,
      expected: state.fed_through,
      arrived: position
    })

    state
    |> resynchronising(position)
    |> resynchronise(position, bytes)
  end

  @spec resynchronising(state(), non_neg_integer()) :: state()
  defp resynchronising(state, position) do
    %{state | decoder: nil, fed_through: nil, resync: {position, <<>>}}
  end

  # A stream is picked up at a section header and nowhere else. What is searched
  # is the bytes in hand plus the few kept from the last shipment, so a header
  # cut across two of them is still found, and the search is bounded by what
  # arrived rather than by anything the appliance can grow.
  @spec resynchronise(state(), non_neg_integer(), binary()) :: state()
  defp resynchronise(state, position, bytes) do
    {base, held} =
      case state.resync do
        {base, held} when base + byte_size(held) == position -> {base, held}
        _discontinuous -> {position, <<>>}
      end

    buffer = held <> bytes

    case :binary.match(buffer, @section_header) do
      {at, _length} ->
        found = base + at
        count_lost(state, found - base - byte_size(held))

        %{state | decoder: Pcapng.new(), fed_through: found, resync: nil}
        |> feed(found, binary_part(buffer, at, byte_size(buffer) - at))

      :nomatch ->
        keep = min(@resync_tail, byte_size(buffer))
        tail = binary_part(buffer, byte_size(buffer) - keep, keep)
        count_lost(state, byte_size(buffer) - byte_size(held) - keep)
        %{state | resync: {base + byte_size(buffer) - keep, tail}}
    end
  end

  # Bytes at or below the cursor are already stored, so the run is cut there and
  # its two halves are fed separately: the first for the decoder's sake alone,
  # the second for its rows. The cursor is always the end of a whole block, so
  # nothing is cut in half by this.
  @spec feed(state(), non_neg_integer(), binary()) :: state()
  defp feed(state, position, bytes) do
    stored = state.cursor - position

    if stored > 0 and stored < byte_size(bytes) do
      state
      |> decode(binary_part(bytes, 0, stored), false)
      |> decode(binary_part(bytes, stored, byte_size(bytes) - stored), true)
    else
      decode(state, bytes, position >= state.cursor)
    end
  end

  @spec decode(state(), binary(), boolean()) :: state()
  defp decode(state, <<>>, _store?), do: state

  defp decode(state, bytes, store?) do
    case Pcapng.decode(state.decoder, bytes) do
      {:ok, blocks, decoder} ->
        fed_through = state.fed_through + byte_size(bytes)

        %{state | decoder: decoder, fed_through: fed_through}
        |> collect(blocks, store?, fed_through - Pcapng.buffered(decoder))
        |> maybe_flush()

      {:error, reason} ->
        refused(state, reason, byte_size(bytes))
    end
  end

  # A refusal carries no state to continue from, and where in the run it
  # happened is not knowable, so the rest of that run is gone. The next shipment
  # is searched for a section header from its own beginning.
  @spec refused(state(), Pcapng.reason(), non_neg_integer()) :: state()
  defp refused(state, reason, size) do
    Logger.warning(
      "ctrld: appliance #{state.device_id} #{state.ring} ring refused at position " <>
        "#{state.fed_through}: #{Pcapng.describe(reason)}"
    )

    Ingest.emit(:decoder_refused, %{bytes: size}, %{
      device_id: state.device_id,
      ring: state.ring,
      reason: elem(reason, 0)
    })

    %{state | decoder: nil, fed_through: nil, resync: nil}
  end

  # Two kinds of block become rows, and they go to different tables: an
  # Enhanced Packet Block is what the appliance decided about a packet, and a
  # Custom Block carrying a metric reading is what its counters read at an
  # instant. Every other block — the section, the interfaces, and the padding
  # that shares a type and an enterprise number with a reading — contributes
  # none, which is why the padding needs no filter of its own here: it arrives
  # as a `%Custom{}` and the decoder below answers `:padding` for it.
  @spec collect(state(), [Pcapng.block()], boolean(), non_neg_integer()) :: state()
  defp collect(state, blocks, store?, complete_through) do
    records = Enum.filter(blocks, &match?(%Packet{}, &1))
    customs = Enum.filter(blocks, &match?(%Custom{}, &1))

    cond do
      records == [] and customs == [] ->
        state

      not store? ->
        Ingest.emit(:records_skipped, %{records: length(records) + length(customs)}, %{
          device_id: state.device_id,
          ring: state.ring,
          cause: :already_stored
        })

        state

      not stores?(state.ring) ->
        Ingest.emit(:records_skipped, %{records: length(records) + length(customs)}, %{
          device_id: state.device_id,
          ring: state.ring,
          cause: :ring_not_stored
        })

        state

      true ->
        flow_rows = Enum.reduce(records, [], &build(&1, &2, state))
        sample_rows = Enum.reduce(customs, [], &sample(&1, &2, state))

        Ingest.emit(:rows_built, %{rows: length(flow_rows) + length(sample_rows)}, %{
          device_id: state.device_id,
          ring: state.ring
        })

        state
        |> hold("flow_events", flow_rows)
        |> hold("metric_samples", sample_rows)
        |> Map.put(:pending_through, complete_through)
    end
  end

  @spec hold(state(), String.t(), [map()]) :: state()
  defp hold(state, _table, []), do: state

  defp hold(state, table, rows),
    do: %{state | pending: Map.update!(state.pending, table, &(rows ++ &1))}

  # A Custom Block is a metric reading or it is the padding that fills a sector,
  # and the leading byte of its data is what tells them apart. Padding is the
  # commoner of the two by far and is not a fault, so it is stepped over in
  # silence; everything else is counted under the cause that named it.
  @spec sample(Custom.t(), [map()], state()) :: [map()]
  defp sample(%Custom{data: data}, rows, state) do
    case MetricSnapshot.rows(state.device_id, data) do
      {:ok, %{rows: built, unrepresentable: 0}} ->
        Enum.reverse(built) ++ rows

      {:ok, %{rows: built, unrepresentable: refused}} ->
        # A counter no `Float64` holds exactly. Refused by name rather than
        # stored rounded: a rounded counter reads as a measurement and nothing
        # downstream can tell it from one.
        Ingest.emit(:samples_skipped, %{samples: refused}, %{
          device_id: state.device_id,
          ring: state.ring,
          cause: :value_unrepresentable
        })

        Enum.reverse(built) ++ rows

      {:error, :padding} ->
        rows

      {:error, refusal} ->
        Ingest.emit(:records_skipped, %{records: 1}, %{
          device_id: state.device_id,
          ring: state.ring,
          cause: MetricSnapshot.tag(refusal)
        })

        rows
    end
  end

  @spec build(Packet.t(), [map()], state()) :: [map()]
  defp build(%Packet{} = record, rows, state) do
    case FlowEvent.row(state.device_id, record) do
      {:row, row, nil} ->
        [row | rows]

      {:row, row, frame_refusal} ->
        # The row still stands: the annotation is what the appliance decided and
        # it is intact. Only the five columns read out of the frame are absent,
        # and the row says so in a shape no readable frame can produce.
        Ingest.emit(:frame_unread, %{records: 1}, %{
          device_id: state.device_id,
          ring: state.ring,
          refusal: refusal_tag(frame_refusal)
        })

        [row | rows]

      {:no_row, refusal} ->
        Ingest.emit(:records_skipped, %{records: 1}, %{
          device_id: state.device_id,
          ring: state.ring,
          cause: refusal_tag(refusal)
        })

        rows
    end
  end

  @spec refusal_tag(atom() | tuple()) :: atom()
  defp refusal_tag(refusal) when is_atom(refusal), do: refusal
  defp refusal_tag(refusal) when is_tuple(refusal), do: elem(refusal, 0)

  @spec maybe_flush(state()) :: state()
  defp maybe_flush(state) do
    cond do
      held(state) >= @batch_rows ->
        {_result, state} = flush(state)
        state

      held(state) == 0 ->
        state

      true ->
        schedule(state)
    end
  end

  # A batch is bounded across both tables together, because what the bound
  # protects is this process's memory and one recording feeds both.
  @spec held(state()) :: non_neg_integer()
  defp held(state), do: state.pending |> Map.values() |> Enum.map(&length/1) |> Enum.sum()

  @spec empty() :: %{String.t() => [map()]}
  defp empty, do: Map.new(@tables, &{&1, []})

  @spec schedule(state()) :: state()
  defp schedule(%{timer: nil} = state),
    do: %{state | timer: Process.send_after(self(), :flush, @batch_age)}

  defp schedule(state), do: state

  # Every table's batch, and the cursor moves only once all of them are in.
  # Advancing it on a partial success would mark bytes as stored whose other
  # table never took them, and the next delivery would skip exactly those.
  @spec flush(state()) :: {:ok | {:error, term()}, state()}
  defp flush(state) do
    if held(state) == 0 do
      {:ok, cancel(state)}
    else
      Enum.reduce(@tables, {:ok, state}, fn table, {result, state} ->
        case insert(state, table) do
          {:ok, state} -> {result, state}
          {{:error, reason}, state} -> {{:error, reason}, state}
        end
      end)
      |> settle()
    end
  end

  @spec insert(state(), String.t()) :: {:ok | {:error, term()}, state()}
  defp insert(state, table) do
    case Map.fetch!(state.pending, table) do
      [] ->
        {:ok, state}

      held ->
        rows = Enum.reverse(held)

        case Store.insert(table, rows) do
          :ok ->
            Ingest.emit(:rows_inserted, %{rows: length(rows)}, %{
              device_id: state.device_id,
              ring: state.ring,
              table: table
            })

            {:ok, %{state | pending: Map.put(state.pending, table, [])}}

          {:error, reason} ->
            {{:error, reason}, retain(state, table, rows, reason)}
        end
    end
  end

  @spec settle({:ok | {:error, term()}, state()}) :: {:ok | {:error, term()}, state()}
  defp settle({:ok, state}), do: {:ok, stored(state)}
  defp settle({{:error, reason}, state}), do: {{:error, reason}, state}

  # The rows are in, so the cursor may name the last block they cover — and
  # only that block, never the bytes that arrived, the run having likely ended
  # inside a block whose rows are not built yet.
  @spec stored(state()) :: state()
  defp stored(%{pending_through: nil} = state),
    do: %{recovered(state) | pending: empty()}

  defp stored(state) do
    :ok = Cursor.advance(state.device_id, state.ring, state.pending_through)

    %{
      recovered(state)
      | pending: empty(),
        pending_through: nil,
        cursor: max(state.cursor, state.pending_through)
    }
  end

  @spec recovered(state()) :: state()
  defp recovered(%{failing?: false} = state), do: cancel(state)

  defp recovered(state) do
    Logger.info(
      "ctrld: appliance #{state.device_id} #{state.ring} ring stored what it was holding"
    )

    %{cancel(state) | failing?: false}
  end

  # A store that refused keeps its rows: the commonest reason is a store that is
  # restarting, and holding them means that costs nothing at all. What it must
  # not cost is this process's memory, so the hold has a bound, and rows dropped
  # at it are named rather than quietly gone.
  #
  # The line is written once per outage rather than once per attempt. Retrying
  # on the age bound is what recovers, and a store that is down for an hour
  # would otherwise write the same sentence eighteen hundred times per ring —
  # which is a record count driven by how long a fault lasted rather than by
  # what happened. Every attempt is still counted.
  @spec retain(state(), String.t(), [map()], term()) :: state()
  defp retain(state, table, rows, reason) do
    unless state.failing? do
      Logger.warning(
        "ctrld: appliance #{state.device_id} #{state.ring} ring could not store " <>
          "#{length(rows)} #{table} rows, and is holding them: #{Store.describe(reason)}"
      )
    end

    Ingest.emit(:insert_failed, %{rows: length(rows)}, %{
      device_id: state.device_id,
      ring: state.ring,
      table: table,
      reason: refusal_tag(reason)
    })

    over = held(state) - @max_pending

    pending =
      if over > 0 do
        Logger.warning(
          "ctrld: appliance #{state.device_id} #{state.ring} ring dropped #{over} telemetry " <>
            "rows the store would not take"
        )

        Ingest.emit(:rows_dropped, %{rows: over}, %{
          device_id: state.device_id,
          ring: state.ring
        })

        trim(state.pending, over)
      else
        state.pending
      end

    retrying = state |> cancel() |> schedule()
    %{retrying | pending: pending, failing?: true}
  end

  # Drop the oldest rows first, and take them from the table that holds the most
  # so one busy table cannot squeeze another out of the hold entirely. The lists
  # are newest-first, so the oldest are at the tail.
  @spec trim(%{String.t() => [map()]}, non_neg_integer()) :: %{String.t() => [map()]}
  defp trim(pending, 0), do: pending

  defp trim(pending, over) do
    {table, rows} = Enum.max_by(pending, fn {_table, rows} -> length(rows) end)
    take = min(over, length(rows))
    pending = Map.put(pending, table, Enum.take(rows, length(rows) - take))
    trim(pending, over - take)
  end

  @spec cancel(state()) :: state()
  defp cancel(%{timer: nil} = state), do: state

  defp cancel(state) do
    _ = Process.cancel_timer(state.timer)
    %{state | timer: nil}
  end

  @spec count_lost(state(), non_neg_integer()) :: :ok
  defp count_lost(state, bytes) when bytes > 0 do
    Ingest.emit(:bytes_lost, %{bytes: bytes}, %{device_id: state.device_id, ring: state.ring})
  end

  defp count_lost(_state, _bytes), do: :ok

  @spec cursor(state()) :: non_neg_integer()
  defp cursor(state) do
    if stores?(state.ring), do: Cursor.position(state.device_id, state.ring), else: 0
  end

  @spec stores?(Frame.ring()) :: boolean()
  defp stores?(ring), do: ring == Ingest.storing_ring()
end
