defmodule Ctrld.Pcapng.Custom do
  @moduledoc """
  A Custom Block: a Private Enterprise Number and bytes only its owner can read.

  In a recording this is the block that fills the slack behind the last record
  of a sector and seals a segment at the roll. Its data is zero, and every
  reader steps over it — which is the whole reason the appliance writes a block
  there rather than leaving bytes a later write would have to complete. The same
  block type is intended to carry metric snapshots and audit records once the
  appliance has a producer for them; it has none yet, so the padding is the only
  custom block a recording holds.

  `data` is everything between the enterprise number and the block's closing
  length, padding included. That is not an oversight but the format: a Custom
  Block states no length for its own data, so where a writer padded an unaligned
  payload to the four-byte boundary those bytes are indistinguishable from the
  payload to anybody but the enterprise that wrote them.
  """

  @enforce_keys [:pen, :data]
  defstruct [:pen, :data]

  @type t :: %__MODULE__{pen: 0..4_294_967_295, data: binary()}
end
