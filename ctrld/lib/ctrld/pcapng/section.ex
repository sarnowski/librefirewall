defmodule Ctrld.Pcapng.Section do
  @moduledoc """
  A Section Header Block: the start of a section, and the only place a
  recording says which byte order it was written in.

  Every ring segment of a recording opens with one, so a stream carries one per
  segment rather than one per connection. A section resets the interface
  numbering that follows it, which is why the decoder treats this block as the
  boundary it is instead of as another record.

  `section_length` is `nil` where the header declares it unspecified, which is
  always the case for a ring being appended to: the length of a section nobody
  has finished writing is not a number the writer has.
  """

  @enforce_keys [:endianness, :major, :minor, :section_length, :options]
  defstruct [:endianness, :major, :minor, :section_length, :options]

  @type t :: %__MODULE__{
          endianness: :little | :big,
          major: non_neg_integer(),
          minor: non_neg_integer(),
          section_length: nil | non_neg_integer(),
          options: Ctrld.Pcapng.options()
        }
end
