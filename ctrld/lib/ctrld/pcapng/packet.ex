defmodule Ctrld.Pcapng.Packet do
  @moduledoc """
  An Enhanced Packet Block: one observation, and what the appliance knew about
  it.

  This is the block the recordings are made of. Everything the appliance
  observed is one of these — the capture holds one per frame it decided on, the
  connection history one per lifecycle or policy event — and the annotation is
  where the firewall's own state rides.

  `timestamp` is the raw tick count the block carries, in the interface's
  resolution; `observed_at` is that count resolved against it. Both are kept
  because they answer different questions: the instant is what a query needs,
  and the ticks are what a record can be compared against its neighbours with,
  no resolution having been applied to either.

  `original_length` exceeds `byte_size(data)` exactly where the sink's snap
  length cut the frame short. Both being zero is not a truncation but the one
  record about no frame at all: a flow the appliance took back needs somewhere
  to say so, and says it here with an empty packet rather than by borrowing the
  last frame the flow saw.
  """

  @enforce_keys [
    :interface_id,
    :timestamp,
    :observed_at,
    :original_length,
    :data,
    :annotation,
    :options
  ]

  defstruct [
    :interface_id,
    :timestamp,
    :observed_at,
    :original_length,
    :data,
    :annotation,
    :options
  ]

  @type t :: %__MODULE__{
          interface_id: 0..4_294_967_295,
          timestamp: non_neg_integer(),
          observed_at: DateTime.t(),
          original_length: 0..4_294_967_295,
          data: binary(),
          annotation: nil | Ctrld.Pcapng.Annotation.t(),
          options: Ctrld.Pcapng.options()
        }
end
