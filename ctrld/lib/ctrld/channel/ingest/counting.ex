defmodule Ctrld.Channel.Ingest.Counting do
  @moduledoc """
  The ingest that counts what arrived and keeps none of it.

  It is the deployed default, and it is a complete implementation of what this
  server can honestly do with ring bytes today: there is no pcapng decoder on
  this side of the wire, so the alternative to counting is storing bytes nothing
  can read back. A tally is the honest answer — how much arrived, for which
  appliance, on which ring — and it is the measurement that says the channel is
  carrying traffic before anything can say what the traffic was.

  The count goes out as a telemetry event and is held nowhere here: this module
  owns no process and no state, so ingest costs the connection an event
  dispatch and nothing else.

  What it never does is put a byte of a payload anywhere. Those bytes are a
  customer's captured network traffic; the event carries their length and the
  appliance and ring they belong to, all of which are system state, and nothing
  that came out of the ring itself.
  """

  alias Ctrld.Channel.Frame

  @behaviour Ctrld.Channel.Ingest

  @doc """
  The telemetry event this module emits per upstream frame.

  Measurements carry `:bytes`, the length of what arrived, and `:position`, the
  ring position it started at. Metadata carries `:device_id` and `:ring`.
  """
  @spec event() :: [atom()]
  def event, do: [:ctrld, :channel, :ingest]

  @impl Ctrld.Channel.Ingest
  @spec ring_bytes(String.t(), Frame.ring(), non_neg_integer(), binary()) :: :ok
  def ring_bytes(device_id, ring, position, bytes)
      when is_binary(device_id) and ring in [:log, :capture] and is_integer(position) and
             is_binary(bytes) do
    :telemetry.execute(
      event(),
      %{bytes: byte_size(bytes), position: position},
      %{device_id: device_id, ring: ring}
    )
  end
end
