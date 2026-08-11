defmodule Ctrld.Pcapng.Statistics do
  @moduledoc """
  An Interface Statistics Block: what one interface had seen and lost as of an
  instant.

  The appliance's encoder can write these and its recorder does not — a
  recording states its loss through each record's drop count instead — so no
  recording shipped up the channel has ever carried one. It is decoded anyway
  because the encoder is the authority on the format and this block is part of
  what it emits: a producer appearing on the appliance side must not be the
  moment this server starts refusing streams.

  The counts themselves are options rather than fields, so they are read out of
  `options` under their own names and are absent where the writer omitted them.
  """

  @enforce_keys [:interface_id, :timestamp, :observed_at, :options]
  defstruct [:interface_id, :timestamp, :observed_at, :options]

  @type t :: %__MODULE__{
          interface_id: 0..4_294_967_295,
          timestamp: non_neg_integer(),
          observed_at: DateTime.t(),
          options: Ctrld.Pcapng.options()
        }
end
