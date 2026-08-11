defmodule Ctrld.Pcapng.Annotation do
  @moduledoc """
  The firewall state a record carries in its PEN-tagged custom option.

  pcapng has no field for what a firewall decided, so the appliance puts it in
  a custom option — code 2989, the copyable binary form — tagged with a Private
  Enterprise Number and holding a fixed 24-byte layout. This module is the
  reading half of that layout; the writing half is the appliance's recorder,
  and the two are the reason this file exists rather than the annotation being
  a blob a later query would have to slice.

  ## The version byte decides, not the length

  The first octet names the layout. This module reads version 3 and nothing
  else: an annotation under any other version is left undecoded and its bytes
  are kept as the raw custom option, which is what lets an appliance one
  version ahead of this server ship recordings that still ingest as packets
  rather than being refused wholesale. A layout is allowed to grow; a reader
  that guessed from the length it happened to see would read a grown one as a
  different record and say nothing.

  ## Why every vocabulary stays a number

  Each of the six enumerated fields is an integer here, not an atom. Two
  reasons, and they point the same way. The vocabularies are the appliance's
  own ABI, versioned by the octet above and larger than they look — twenty-six
  drop reasons, twelve flow states — so a name resolved here would be a second
  copy of a table that lives in another language and could drift from it
  silently. And the number is what every column these records land in holds, so
  carrying it is lossless where a name would need an inverse table to undo.
  A code this build has never heard of therefore costs nothing: no atom is
  invented for it, nothing is dropped, and nothing is refused.

  ## The layout has its own byte order

  The three words below are little-endian whatever byte order the section
  around them was written in. An option value is opaque to pcapng, so its
  interior is this layout's business and not the section header's — the
  appliance writes them little-endian unconditionally, and a reader that
  reached for the section's byte order here would read a big-endian section's
  annotations byte-reversed.

  ## Zero means absent

  Four fields use zero for *nothing here* rather than for a member:
  `drop_reason` on a frame that was not dropped, `classification` and
  `flow_state` on an observation about no flow, `event` on a packet the capture
  holds alone, and `matched_rule` where no rule was consulted. A rule is
  therefore stored one higher than its position — `matched_rule` of 1 is the
  first rule of the generation — and that encoding is preserved rather than
  decoded away, because it is the encoding the target column holds.
  """

  @version 3
  @length 24

  @enforce_keys [
    :version,
    :verdict,
    :drop_reason,
    :interface_id,
    :direction,
    :classification,
    :event,
    :flow_state,
    :generation,
    :flow_slot,
    :flow_generation,
    :matched_rule
  ]

  defstruct [
    :version,
    :verdict,
    :drop_reason,
    :interface_id,
    :direction,
    :classification,
    :event,
    :flow_state,
    :generation,
    :flow_slot,
    :flow_generation,
    :matched_rule
  ]

  @type t :: %__MODULE__{
          version: 3,
          verdict: 0..255,
          drop_reason: 0..255,
          interface_id: 0..255,
          direction: 0..255,
          classification: 0..255,
          event: 0..255,
          flow_state: 0..255,
          generation: 0..4_294_967_295,
          flow_slot: 0..4_294_967_295,
          flow_generation: 0..4_294_967_295,
          matched_rule: 0..65_535
        }

  @doc "The layout version this module reads."
  @spec version() :: pos_integer()
  def version, do: @version

  @doc "The bytes a version #{@version} annotation occupies."
  @spec length() :: pos_integer()
  def length, do: @length

  @doc """
  Decode an annotation, or answer `:unrecognised` for a layout this build does
  not read.

  `:unrecognised` is deliberately not an error. The caller keeps the raw option
  either way, so an unread annotation costs the annotation and never the record
  it rides on.

  The two octets behind `matched_rule` are not examined: version #{@version}
  does not define them, and a reader that refused what a version leaves unsaid
  would refuse the version that starts saying it.
  """
  @spec decode(binary()) :: {:ok, t()} | :unrecognised
  def decode(
        <<@version, verdict, drop_reason, interface_id, direction, classification, event,
          flow_state, generation::unsigned-little-32, flow_slot::unsigned-little-32,
          flow_generation::unsigned-little-32, matched_rule::unsigned-little-16, _undefined::16>>
      ) do
    {:ok,
     %__MODULE__{
       version: @version,
       verdict: verdict,
       drop_reason: drop_reason,
       interface_id: interface_id,
       direction: direction,
       classification: classification,
       event: event,
       flow_state: flow_state,
       generation: generation,
       flow_slot: flow_slot,
       flow_generation: flow_generation,
       matched_rule: matched_rule
     }}
  end

  def decode(bytes) when is_binary(bytes), do: :unrecognised
end
