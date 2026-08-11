defmodule Ctrld.Pcapng.Interface do
  @moduledoc """
  An Interface Description Block: one of the appliance's ports, as the section
  describes it.

  `id` is not a field on the wire. Blocks refer to an interface by the position
  of its description within the section, counting from zero, so the decoder
  numbers these as they arrive and every later record is resolved against that
  numbering.

  `timestamp_digits` is what makes a record's timestamp a time. The block states
  it as a resolution option, and where the option is absent the format's own
  default of microseconds applies — so this is always a number and never an
  assumption a reader has to make for itself.
  """

  @enforce_keys [:id, :link_type, :snap_len, :timestamp_digits, :options]
  defstruct [:id, :link_type, :snap_len, :timestamp_digits, :options]

  @type t :: %__MODULE__{
          id: non_neg_integer(),
          link_type: 0..65_535,
          snap_len: 0..4_294_967_295,
          timestamp_digits: 0..127,
          options: Ctrld.Pcapng.options()
        }
end
