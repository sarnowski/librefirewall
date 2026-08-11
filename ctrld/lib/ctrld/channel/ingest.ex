defmodule Ctrld.Channel.Ingest do
  @moduledoc """
  Where the recording bytes an appliance ships go, and the seam they cross.

  The two upstream frames carry a recording ring's own bytes, verbatim, from a
  stated position: the ring bytes are the wire bytes and the appliance
  re-encodes nothing. This module is the one boundary those bytes cross on the
  way out of the channel, and it is deliberately the whole of it — the session
  above hands over a device, a ring, a position and a run of bytes, and knows
  nothing about what reads them.

  That split is not tidiness. What is inside those bytes is pcapng, and decoding
  pcapng from an appliance is parsing an untrusted, self-describing format —
  a different job facing the same adversary, with its own bounds to hold and its
  own refusals to name. Putting it behind a callback keeps the transport's
  correctness arguable without it, and keeps a decoder's failure from being a
  framing failure: bytes that arrived as a well-formed frame *were* a well-formed
  frame, whatever their contents turn out to be.

  ## What an implementation may assume, and what it may not

  It may assume the bytes arrived inside a frame this server's own codec
  accepted, from an appliance whose certificate this server issued and whose row
  it found — so `device_id` names a real appliance and `ring` is one of two
  values.

  It may assume nothing whatever about the bytes. They are a compromised
  appliance's to choose, `position` is a number it chose too, and delivery is
  at-least-once: the same bytes at the same position arrive again across a
  reconnect, by design, so an implementation is idempotent or it is wrong.

  ## What an implementation must not do

  Block. The callback runs on the connection's own process, so time spent in it
  is time the appliance's stream is not read. An implementation with work to do
  hands it to something else and returns.

  It must also keep the bytes off every operational surface: a recording is one
  of the two artifacts allowed to carry traffic, and a log line is not.
  """

  alias Ctrld.Channel.Frame

  @doc """
  Take the ring bytes one upstream frame carried.

  `position` is the byte position in the ring's own append space that `bytes`
  begin at — the same coordinate the ring's superblock keeps — and not an offset
  into anything this server holds.

  The return value is `:ok` and nothing else. There is no refusal an
  implementation can return, because there is nothing the channel could do with
  one: the bytes are already on this side of the wire, the appliance is owed no
  answer to a frame it has already sent, and a session that closed over a
  problem with the ingest would be re-established a second later and hand over
  the same bytes again. An implementation that cannot store what it was given
  says so where it can be acted on — its own logs and metrics — and the
  acknowledgement cursor is what eventually tells the appliance how far this
  server got.
  """
  @callback ring_bytes(
              device_id :: String.t(),
              ring :: Frame.ring(),
              position :: non_neg_integer(),
              bytes :: binary()
            ) :: :ok

  @doc """
  The implementation this deployment ingests through.

  Configured rather than named at the call site, which is what lets the pcapng
  decode and the telemetry write sit behind this seam without the channel
  knowing they are there — and what lets a suite about the channel run against
  an ingest that holds nothing.

  The default is the one a deployment wants rather than the one that costs
  least: a configuration that lost this line would otherwise throw a fleet's
  recordings away and say nothing, and an ingest is not a thing to degrade
  quietly into.
  """
  @spec configured() :: module()
  def configured do
    Application.get_env(:ctrld, __MODULE__, [])
    |> Keyword.get(:handler, Ctrld.Channel.Ingest.Telemetry)
  end

  @doc "Hand `bytes` to the configured implementation."
  @spec ring_bytes(String.t(), Frame.ring(), non_neg_integer(), binary()) :: :ok
  def ring_bytes(device_id, ring, position, bytes) do
    configured().ring_bytes(device_id, ring, position, bytes)
  end
end
