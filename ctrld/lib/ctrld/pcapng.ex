defmodule Ctrld.Pcapng do
  @moduledoc """
  Reading the recordings an appliance ships, block by block, as they arrive.

  An appliance records what it observed as pcapng into two rings and sends those
  rings' own bytes up the channel verbatim — the ring bytes are the wire bytes,
  and nothing re-encodes them on the way. So this is where a recording becomes
  something this server can store: the reading half of a format whose writing
  half is the appliance's encoder, in another language, in the other component.

  That is the risk this module is arranged around. Two implementations of one
  format can agree for a long time and then quietly stop, and the failure runs
  in the worst direction available — a field read at the wrong offset yields a
  plausible number, not an error. Two things answer it. Every rule the encoder
  states is checked here rather than assumed, so a stream that has left the
  contract is refused by name instead of decoded into the wrong record. And the
  suite reads bytes that encoder actually produced, committed as fixtures,
  rather than bytes a helper here wrote to its own understanding of the format.

  ## Incremental by construction

  Bytes arrive in whatever pieces the transport had, and a block spans them.
  `decode/2` therefore takes the state a previous call returned, appends what
  arrived, and answers with every whole block it can now see and a state holding
  the remainder. A partial block is held rather than guessed at, and nothing is
  taken past the end of the block being decoded — so one stream cut at any point
  yields the same blocks in the same order as the whole of it at once.

  ## Bounded against the peer

  An appliance is authenticated but only semi-trusted, and the bytes it ships
  derive from network traffic that is not trusted at all. A block's declared
  length is therefore judged against `max_block_bytes/0` **before** anything is
  buffered for it, so a peer declaring a gigabyte is refused after twelve bytes
  rather than after a gigabyte; what that leaves held is one partial block and
  never more. The interface table a section builds is bounded the same way, by
  `max_interfaces/0`, that table being the only other state a peer could choose
  the size of.

  Both walks here consume before they recur — a block costs at least the twelve
  bytes of its framing, an option at least the four of its header — so neither
  can be made to spin by anything a peer sends.

  ## Refusal is total, and it ends the stream

  Nothing raises and nothing crashes: every way these bytes can be wrong is a
  named reason `decode/2` returns. A refusal ends the stream rather than being
  skipped past, because a block this reader cannot agree with is a block whose
  successor's offset is no longer known — resynchronising would be guessing, and
  a recording is evidence. The caller closes the connection, and the appliance
  resumes from the cursor it was last acknowledged at, which is what makes
  ending a stream affordable rather than lossy.

  ## What comes out

  One struct per block type, and on a record the decoded annotation beside its
  raw option: `Ctrld.Pcapng.Annotation` carries the flow, the rule and the event
  the appliance decided. Those fields and the resolved instant next to them are
  what a stored row is made of. This module produces a row's values and stores
  nothing itself.
  """

  alias Ctrld.Pcapng.{Annotation, Custom, Interface, Packet, Section, Statistics}

  # Written by the appliance as 0x0A0D0D0A, which is a byte-order palindrome —
  # deliberately, since it is what lets a section header be recognised before the
  # byte order it declares has been read.
  @section_header <<0x0A, 0x0D, 0x0D, 0x0A>>
  @section_header_type 0x0A0D_0D0A

  @interface_description 0x0000_0001
  @interface_statistics 0x0000_0005
  @enhanced_packet 0x0000_0006
  @custom_block 0x0000_0BAD

  # 0x1A2B3C4D as the writer laid it down: found in this order the section is
  # little-endian, found reversed it is big-endian.
  @magic_little <<0x4D, 0x3C, 0x2B, 0x1A>>
  @magic_big <<0x1A, 0x2B, 0x3C, 0x4D>>

  # The only major version the appliance writes, and the only one whose block
  # layouts this module knows. Accepting a major version it does not know would
  # be reading fields at offsets nobody promised.
  @major 1

  # Block type, block total length, and the repeated block total length.
  @framing 12

  # The smallest each block can be — its framing plus the fixed body its type
  # always has. These are the encoder's own minima, and a block below one of them
  # cannot hold the fields its type is read for.
  @minimum %{
    @section_header_type => @framing + 16,
    @interface_description => @framing + 8,
    @interface_statistics => @framing + 12,
    @enhanced_packet => @framing + 20,
    @custom_block => @framing + 4
  }

  @alignment 4

  @option_end 0

  # One block can never exceed one ring segment, and a sealed segment is what the
  # channel's frame bound is sized for — so a mebibyte is the bound both ends
  # already agree on rather than a number invented here.
  @max_block_bytes 1_048_576

  # Well above the eight ports the appliance's configuration schema admits, so a
  # port count that grows over there does not start being refused over here, and
  # still a bound.
  @max_interfaces 64

  defstruct buffer: <<>>, endianness: nil, interfaces: %{}, interface_count: 0

  @typedoc """
  A decoder between calls: the bytes of a block that has not all arrived, the
  byte order the current section declared, and the interfaces it has described.
  """
  @type t :: %__MODULE__{
          buffer: binary(),
          endianness: nil | :little | :big,
          interfaces: %{optional(non_neg_integer()) => Interface.t()},
          interface_count: non_neg_integer()
        }

  @type block :: Section.t() | Interface.t() | Packet.t() | Statistics.t() | Custom.t()

  @typedoc """
  A block's options, in the order they were written.

  A code the appliance writes is named and its value decoded; one it does not
  write is left as the number it arrived as with its bytes unread, so an option
  this build has not heard of is carried rather than dropped.
  """
  @type options :: [{atom() | non_neg_integer(), term()}]

  # How one block type names its option codes. The code space is per block, so
  # each type brings its own table and a code no table names is left unread.
  @typep table :: (non_neg_integer() -> {atom(), term()} | nil)

  @type reason ::
          {:not_a_section_header, binary()}
          | {:bad_byte_order_magic, binary()}
          | {:unsupported_section_version, non_neg_integer(), non_neg_integer()}
          | {:unknown_block_type, non_neg_integer()}
          | {:block_too_short, non_neg_integer(), non_neg_integer(), pos_integer()}
          | {:block_too_long, non_neg_integer(), non_neg_integer(), pos_integer()}
          | {:block_length_not_aligned, non_neg_integer(), non_neg_integer()}
          | {:length_trailer_mismatch, non_neg_integer(), non_neg_integer(), non_neg_integer()}
          | {:packet_exceeds_block, non_neg_integer(), non_neg_integer()}
          | {:captured_exceeds_original, non_neg_integer(), non_neg_integer()}
          | {:payload_padding_not_zero, non_neg_integer()}
          | {:truncated_option, non_neg_integer(), non_neg_integer(), non_neg_integer()}
          | {:unterminated_options, non_neg_integer()}
          | {:trailing_option_bytes, non_neg_integer(), non_neg_integer()}
          | {:option_padding_not_zero, non_neg_integer(), non_neg_integer()}
          | {:option_terminator_not_empty, non_neg_integer()}
          | {:option_length_unexpected, non_neg_integer(), non_neg_integer(), non_neg_integer(),
             pos_integer()}
          | {:unsupported_timestamp_resolution, 0..255}
          | {:unknown_interface, non_neg_integer()}
          | {:too_many_interfaces, pos_integer()}
          | {:timestamp_out_of_range, non_neg_integer()}

  @doc "A decoder that has seen nothing."
  @spec new() :: t()
  def new, do: %__MODULE__{}

  @doc """
  The largest block this decoder will buffer, in bytes.

  It bounds what a peer can make this server hold: a declared length past it is
  refused before a byte is kept for it, so the buffer never exceeds it however
  the stream is cut.
  """
  @spec max_block_bytes() :: pos_integer()
  def max_block_bytes, do: @max_block_bytes

  @doc "The most interfaces one section may describe."
  @spec max_interfaces() :: pos_integer()
  def max_interfaces, do: @max_interfaces

  @doc "Bytes of a block that has not all arrived yet."
  @spec buffered(t()) :: non_neg_integer()
  def buffered(%__MODULE__{buffer: buffer}), do: byte_size(buffer)

  @doc """
  Decode what has arrived.

  Answers every whole block the buffer now holds, in the order the appliance
  wrote them, and a decoder carrying the rest. Handing it `<<>>` is how a caller
  asks whether a held block has become decodable, and answers no blocks where it
  has not.

  A refusal carries no state to continue from, deliberately: a block this reader
  will not agree with is a block whose successor's offset is no longer known.
  """
  @spec decode(t(), binary()) :: {:ok, [block()], t()} | {:error, reason()}
  def decode(%__MODULE__{} = decoder, bytes) when is_binary(bytes) do
    take(%{decoder | buffer: decoder.buffer <> bytes}, [])
  end

  @doc "A refusal in the words an operator reading it needs."
  @spec describe(reason()) :: String.t()
  def describe({:not_a_section_header, type}),
    do: "a stream opens on block type #{hex(type)} rather than on a section header"

  def describe({:bad_byte_order_magic, magic}),
    do: "a section header carries #{hex(magic)} where its byte-order magic belongs"

  def describe({:unsupported_section_version, major, minor}),
    do: "a section states pcapng version #{major}.#{minor}, and this reader has only #{@major}.0"

  def describe({:unknown_block_type, type}),
    do: "block type #{type} is not one the appliance writes"

  def describe({:block_too_short, type, total, minimum}),
    do: "a #{total}-byte block of type #{type} is below the #{minimum} its fields need"

  def describe({:block_too_long, type, total, bound}),
    do: "a block of type #{type} declares #{total} bytes, past this reader's bound of #{bound}"

  def describe({:block_length_not_aligned, type, total}),
    do: "a block of type #{type} declares #{total} bytes, not a multiple of #{@alignment}"

  def describe({:length_trailer_mismatch, type, total, trailer}),
    do: "a block of type #{type} opens on #{total} bytes and closes on #{trailer}"

  def describe({:packet_exceeds_block, captured, available}),
    do: "a record states #{captured} captured bytes with #{available} left in its block"

  def describe({:captured_exceeds_original, captured, original}),
    do: "a record captured #{captured} bytes of a frame that was #{original} on the wire"

  def describe({:payload_padding_not_zero, type}),
    do: "a block of type #{type} pads its payload with bytes that are not zero"

  def describe({:truncated_option, type, code, declared}),
    do: "option #{code} of a block of type #{type} states #{declared} bytes and the block ends"

  def describe({:unterminated_options, type}),
    do: "the options of a block of type #{type} end without a terminator"

  def describe({:trailing_option_bytes, type, count}),
    do: "#{count} bytes follow the option terminator of a block of type #{type}"

  def describe({:option_padding_not_zero, type, code}),
    do: "option #{code} of a block of type #{type} is padded with bytes that are not zero"

  def describe({:option_terminator_not_empty, declared}),
    do: "an option terminator states #{declared} bytes, and it carries none"

  def describe({:option_length_unexpected, type, code, declared, expected}) do
    "option #{code} of a block of type #{type} carries #{declared} bytes " <>
      "where its field is #{expected}"
  end

  def describe({:unsupported_timestamp_resolution, octet}),
    do: "an interface states resolution octet #{octet}, the power-of-two form this reader has not"

  def describe({:unknown_interface, id}),
    do: "a record names interface #{id}, which its section never described"

  def describe({:too_many_interfaces, bound}),
    do: "a section describes more than the #{bound} interfaces this reader holds"

  def describe({:timestamp_out_of_range, ticks}),
    do: "a timestamp of #{ticks} ticks is not an instant"

  # Every recursion consumes a whole block from a finite buffer, and a block is
  # at least the framing wide, so the walk is bounded by the bytes in hand.
  @spec take(t(), [block()]) :: {:ok, [block()], t()} | {:error, reason()}
  defp take(%__MODULE__{} = decoder, decoded) do
    case next(decoder) do
      {:ok, block, decoder} -> take(decoder, [block | decoded])
      :incomplete -> {:ok, Enum.reverse(decoded), decoder}
      {:error, reason} -> {:error, reason}
    end
  end

  @spec next(t()) :: {:ok, block(), t()} | :incomplete | {:error, reason()}
  defp next(%__MODULE__{buffer: <<@section_header, rest::binary>>} = decoder) do
    # A section states its byte order inside its body, which therefore has to be
    # read before the length field that precedes it can be.
    case rest do
      <<length::binary-size(4), magic::binary-size(4), _::binary>> ->
        with {:ok, endianness} <- byte_order(magic) do
          framed(decoder, @section_header_type, uint(length, endianness), endianness)
        end

      _ ->
        :incomplete
    end
  end

  defp next(%__MODULE__{endianness: nil, buffer: <<type::binary-size(4), _::binary>>}),
    do: {:error, {:not_a_section_header, type}}

  defp next(%__MODULE__{endianness: nil}), do: :incomplete

  defp next(%__MODULE__{endianness: endianness, buffer: buffer} = decoder) do
    case buffer do
      <<type::binary-size(4), length::binary-size(4), _::binary>> ->
        framed(decoder, uint(type, endianness), uint(length, endianness), endianness)

      _ ->
        :incomplete
    end
  end

  # The declared length is judged in full before the bytes it claims are waited
  # for. That ordering is the whole bound: it makes what this server holds a
  # consequence of the length a peer stated rather than of how long it keeps
  # sending.
  @spec framed(t(), non_neg_integer(), non_neg_integer(), :little | :big) ::
          {:ok, block(), t()} | :incomplete | {:error, reason()}
  defp framed(%__MODULE__{} = decoder, type, total, endianness) do
    with {:ok, minimum} <- minimum(type),
         :ok <- check_length(type, total, minimum),
         {:ok, body, rest} <- whole(decoder.buffer, type, total, endianness),
         {:ok, block, decoder} <- block(decoder, type, body, endianness) do
      {:ok, block, %{decoder | buffer: rest}}
    end
  end

  @spec minimum(non_neg_integer()) :: {:ok, pos_integer()} | {:error, reason()}
  defp minimum(type) do
    case Map.fetch(@minimum, type) do
      {:ok, minimum} -> {:ok, minimum}
      :error -> {:error, {:unknown_block_type, type}}
    end
  end

  @spec check_length(non_neg_integer(), non_neg_integer(), pos_integer()) ::
          :ok | {:error, reason()}
  defp check_length(type, total, minimum) do
    cond do
      total > @max_block_bytes -> {:error, {:block_too_long, type, total, @max_block_bytes}}
      total < minimum -> {:error, {:block_too_short, type, total, minimum}}
      rem(total, @alignment) != 0 -> {:error, {:block_length_not_aligned, type, total}}
      true -> :ok
    end
  end

  # A block is framed by two copies of one number, and a reader navigating
  # backwards through a ring steps by the second. The pair disagreeing is the one
  # corruption that would otherwise put every later block at an offset nobody can
  # find, so it is checked here and never taken on trust.
  @spec whole(binary(), non_neg_integer(), non_neg_integer(), :little | :big) ::
          {:ok, binary(), binary()} | :incomplete | {:error, reason()}
  defp whole(buffer, type, total, endianness) do
    body_size = total - @framing

    case buffer do
      <<_type::binary-size(4), _length::binary-size(4), body::binary-size(body_size),
        trailer::binary-size(4), rest::binary>> ->
        # In the section's own byte order, never in whichever order would agree:
        # a trailer that only matches reversed is a disagreement, not a dialect.
        case uint(trailer, endianness) do
          ^total -> {:ok, body, rest}
          other -> {:error, {:length_trailer_mismatch, type, total, other}}
        end

      _ ->
        :incomplete
    end
  end

  @spec block(t(), non_neg_integer(), binary(), :little | :big) ::
          {:ok, block(), t()} | {:error, reason()}
  defp block(decoder, @section_header_type, body, endianness) do
    <<_magic::binary-size(4), major::binary-size(2), minor::binary-size(2),
      section_length::binary-size(8), option_bytes::binary>> = body

    major = uint(major, endianness)
    minor = uint(minor, endianness)

    with :ok <- check_version(major, minor),
         {:ok, options} <-
           options(@section_header_type, option_bytes, endianness, &section_option/1) do
      section = %Section{
        endianness: endianness,
        major: major,
        minor: minor,
        section_length: section_length(section_length, endianness),
        options: options
      }

      # A section restarts the interface numbering every later block resolves
      # against, so the table it replaces cannot be carried over the boundary.
      {:ok, section, %{decoder | endianness: endianness, interfaces: %{}, interface_count: 0}}
    end
  end

  defp block(decoder, @interface_description, body, endianness) do
    <<link_type::binary-size(2), _reserved::binary-size(2), snap_len::binary-size(4),
      option_bytes::binary>> = body

    with :ok <- room_for_interface(decoder),
         {:ok, options} <-
           options(@interface_description, option_bytes, endianness, &interface_option/1),
         {:ok, digits} <- timestamp_digits(options) do
      interface = %Interface{
        id: decoder.interface_count,
        link_type: uint(link_type, endianness),
        snap_len: uint(snap_len, endianness),
        timestamp_digits: digits,
        options: options
      }

      {:ok, interface,
       %{
         decoder
         | interfaces: Map.put(decoder.interfaces, interface.id, interface),
           interface_count: decoder.interface_count + 1
       }}
    end
  end

  defp block(decoder, @enhanced_packet, body, endianness) do
    <<interface_id::binary-size(4), high::binary-size(4), low::binary-size(4),
      captured::binary-size(4), original::binary-size(4), payload::binary>> = body

    interface_id = uint(interface_id, endianness)
    captured = uint(captured, endianness)
    original = uint(original, endianness)
    ticks = timestamp(high, low, endianness)

    with {:ok, data, option_bytes} <- packet_payload(payload, captured),
         :ok <- check_captured(captured, original),
         {:ok, options} <- options(@enhanced_packet, option_bytes, endianness, &packet_option/1),
         {:ok, observed_at} <- instant(decoder, interface_id, ticks) do
      packet = %Packet{
        interface_id: interface_id,
        timestamp: ticks,
        observed_at: observed_at,
        original_length: original,
        data: data,
        annotation: annotation(options),
        options: options
      }

      {:ok, packet, decoder}
    end
  end

  defp block(decoder, @interface_statistics, body, endianness) do
    <<interface_id::binary-size(4), high::binary-size(4), low::binary-size(4),
      option_bytes::binary>> = body

    interface_id = uint(interface_id, endianness)
    ticks = timestamp(high, low, endianness)

    with {:ok, options} <-
           options(@interface_statistics, option_bytes, endianness, &statistics_option/1),
         {:ok, observed_at} <- instant(decoder, interface_id, ticks) do
      statistics = %Statistics{
        interface_id: interface_id,
        timestamp: ticks,
        observed_at: observed_at,
        options: options
      }

      {:ok, statistics, decoder}
    end
  end

  defp block(decoder, @custom_block, body, endianness) do
    <<pen::binary-size(4), data::binary>> = body
    {:ok, %Custom{pen: uint(pen, endianness), data: data}, decoder}
  end

  @spec check_version(non_neg_integer(), non_neg_integer()) :: :ok | {:error, reason()}
  defp check_version(@major, _minor), do: :ok
  defp check_version(major, minor), do: {:error, {:unsupported_section_version, major, minor}}

  # All ones is the format's way of saying nobody knows yet, which is every
  # section of a ring still being appended to.
  @spec section_length(binary(), :little | :big) :: nil | non_neg_integer()
  defp section_length(bytes, endianness) do
    case uint(bytes, endianness) do
      0xFFFF_FFFF_FFFF_FFFF -> nil
      length -> length
    end
  end

  @spec room_for_interface(t()) :: :ok | {:error, reason()}
  defp room_for_interface(%__MODULE__{interface_count: count}) when count < @max_interfaces,
    do: :ok

  defp room_for_interface(%__MODULE__{}), do: {:error, {:too_many_interfaces, @max_interfaces}}

  @spec packet_payload(binary(), non_neg_integer()) ::
          {:ok, binary(), binary()} | {:error, reason()}
  defp packet_payload(payload, captured) do
    padding = padding_for(captured)

    case payload do
      <<data::binary-size(captured), pad::binary-size(padding), options::binary>> ->
        # The appliance zeroes what it pads rather than stepping over it, so that
        # a block never carries whatever the ring held there before. Padding that
        # is not zero is the ring bleeding through, which is worth a refusal.
        if zero?(pad) do
          {:ok, data, options}
        else
          {:error, {:payload_padding_not_zero, @enhanced_packet}}
        end

      _ ->
        {:error, {:packet_exceeds_block, captured, byte_size(payload)}}
    end
  end

  @spec check_captured(non_neg_integer(), non_neg_integer()) :: :ok | {:error, reason()}
  defp check_captured(captured, original) when captured <= original, do: :ok

  defp check_captured(captured, original),
    do: {:error, {:captured_exceeds_original, captured, original}}

  # The format splits a timestamp into two 32-bit halves, high word first, each
  # in the section's byte order. Reading the pair as one 64-bit number of that
  # order yields an instant roughly four billion seconds from the truth.
  @spec timestamp(binary(), binary(), :little | :big) :: non_neg_integer()
  defp timestamp(high, low, endianness) do
    uint(high, endianness) * 0x1_0000_0000 + uint(low, endianness)
  end

  # A tick count is a time only in the resolution its interface declared, so a
  # record naming an interface no section described has nothing to resolve
  # against. No correct appliance writes one and no pcapng reader can render one,
  # so it is refused rather than stored against a guessed resolution.
  @spec instant(t(), non_neg_integer(), non_neg_integer()) ::
          {:ok, DateTime.t()} | {:error, reason()}
  defp instant(%__MODULE__{interfaces: interfaces}, interface_id, ticks) do
    case Map.fetch(interfaces, interface_id) do
      {:ok, %Interface{timestamp_digits: digits}} -> from_ticks(ticks, digits)
      :error -> {:error, {:unknown_interface, interface_id}}
    end
  end

  @spec from_ticks(non_neg_integer(), 0..127) :: {:ok, DateTime.t()} | {:error, reason()}
  defp from_ticks(ticks, digits) do
    microseconds =
      cond do
        digits == 6 -> ticks
        digits < 6 -> ticks * Integer.pow(10, 6 - digits)
        true -> div(ticks, Integer.pow(10, digits - 6))
      end

    case DateTime.from_unix(microseconds, :microsecond) do
      {:ok, instant} -> {:ok, instant}
      {:error, _reason} -> {:error, {:timestamp_out_of_range, ticks}}
    end
  end

  @spec timestamp_digits(options()) :: {:ok, 0..127} | {:error, reason()}
  defp timestamp_digits(options) do
    case Keyword.fetch(options, :if_tsresol) do
      # Microseconds is the format's own default, so an interface that states no
      # resolution still has one and no reader has to assume it.
      :error -> {:ok, 6}
      {:ok, {:decimal, digits}} -> {:ok, digits}
      {:ok, {:power_of_two, bits}} -> {:error, {:unsupported_timestamp_resolution, 0x80 + bits}}
    end
  end

  # An annotation under a layout version this build does not read leaves the
  # record whole and its raw option in place. That is what lets an appliance one
  # version ahead ship recordings this server still ingests as packets.
  @spec annotation(options()) :: nil | Annotation.t()
  defp annotation(options) do
    with {:ok, {_pen, data}} <- Keyword.fetch(options, :custom_binary),
         {:ok, annotation} <- Annotation.decode(data) do
      annotation
    else
      _ -> nil
    end
  end

  # The option codes the appliance writes, per block type, because the code space
  # is per block: 2 is the section's hardware, an interface's name, a record's
  # flags and a statistic's start time, and reading one as another is exactly the
  # silent misread this table exists to prevent.
  @spec section_option(non_neg_integer()) :: {atom(), term()} | nil
  defp section_option(1), do: {:comment, :text}
  defp section_option(2), do: {:shb_hardware, :text}
  defp section_option(3), do: {:shb_os, :text}
  defp section_option(4), do: {:shb_userappl, :text}
  defp section_option(2989), do: {:custom_binary, :custom}
  defp section_option(_code), do: nil

  @spec interface_option(non_neg_integer()) :: {atom(), term()} | nil
  defp interface_option(1), do: {:comment, :text}
  defp interface_option(2), do: {:if_name, :text}
  defp interface_option(3), do: {:if_description, :text}
  defp interface_option(8), do: {:if_speed, {:uint, 8}}
  defp interface_option(9), do: {:if_tsresol, :resolution}
  defp interface_option(2989), do: {:custom_binary, :custom}
  defp interface_option(_code), do: nil

  @spec packet_option(non_neg_integer()) :: {atom(), term()} | nil
  defp packet_option(1), do: {:comment, :text}
  defp packet_option(2), do: {:epb_flags, {:uint, 4}}
  defp packet_option(4), do: {:epb_dropcount, {:uint, 8}}
  defp packet_option(5), do: {:epb_packetid, {:uint, 8}}
  defp packet_option(6), do: {:epb_queue, {:uint, 4}}
  defp packet_option(7), do: {:epb_verdict, :verdict}
  defp packet_option(2989), do: {:custom_binary, :custom}
  defp packet_option(_code), do: nil

  @spec statistics_option(non_neg_integer()) :: {atom(), term()} | nil
  defp statistics_option(1), do: {:comment, :text}
  defp statistics_option(2), do: {:isb_starttime, :timestamp}
  defp statistics_option(3), do: {:isb_endtime, :timestamp}
  defp statistics_option(4), do: {:isb_ifrecv, {:uint, 8}}
  defp statistics_option(5), do: {:isb_ifdrop, {:uint, 8}}
  defp statistics_option(2989), do: {:custom_binary, :custom}
  defp statistics_option(_code), do: nil

  # A custom block's bytes are all data: the appliance writes no options on one,
  # and the format states no length for its payload, so there is nothing a reader
  # could tell an option from.

  @spec options(non_neg_integer(), binary(), :little | :big, table()) ::
          {:ok, options()} | {:error, reason()}
  defp options(_type, <<>>, _endianness, _table) do
    # A block with no options carries no option area at all, not even a
    # terminator, so an empty area is complete rather than unterminated.
    {:ok, []}
  end

  defp options(type, bytes, endianness, table),
    do: walk_options(type, bytes, endianness, table, [])

  # Every recursion consumes at least an option header from a finite slice, so
  # this walk is bounded by the block whose length the peer already had to state.
  @spec walk_options(non_neg_integer(), binary(), :little | :big, table(), options()) ::
          {:ok, options()} | {:error, reason()}
  defp walk_options(type, bytes, endianness, table, acc) do
    case bytes do
      <<code::binary-size(2), length::binary-size(2), rest::binary>> ->
        option(
          type,
          uint(code, endianness),
          uint(length, endianness),
          rest,
          endianness,
          table,
          acc
        )

      # An area that ran out is an area that never closed, whether what remains
      # is nothing or too little to read a header from. Both are one fact, and
      # the second is unreachable besides: a block's length is a multiple of four
      # and every option consumes a multiple of four, so what is left over is too.
      _exhausted ->
        {:error, {:unterminated_options, type}}
    end
  end

  @spec option(
          non_neg_integer(),
          non_neg_integer(),
          non_neg_integer(),
          binary(),
          :little | :big,
          table(),
          options()
        ) :: {:ok, options()} | {:error, reason()}
  defp option(type, @option_end, length, rest, _endianness, _table, acc) do
    cond do
      length != 0 -> {:error, {:option_terminator_not_empty, length}}
      # The terminator is the last thing in the area the appliance writes, so
      # bytes behind it are bytes this reader cannot account for.
      rest != <<>> -> {:error, {:trailing_option_bytes, type, byte_size(rest)}}
      true -> {:ok, Enum.reverse(acc)}
    end
  end

  defp option(type, code, length, rest, endianness, table, acc) do
    padding = padding_for(length)

    case rest do
      <<raw::binary-size(length), pad::binary-size(padding), tail::binary>> ->
        if zero?(pad) do
          with {:ok, entry} <- value(type, code, raw, endianness, table) do
            walk_options(type, tail, endianness, table, [entry | acc])
          end
        else
          {:error, {:option_padding_not_zero, type, code}}
        end

      _ ->
        {:error, {:truncated_option, type, code, length}}
    end
  end

  @spec value(non_neg_integer(), non_neg_integer(), binary(), :little | :big, table()) ::
          {:ok, {atom() | non_neg_integer(), term()}} | {:error, reason()}
  defp value(type, code, raw, endianness, table) do
    case table.(code) do
      nil -> {:ok, {code, raw}}
      {name, shape} -> shaped(type, code, name, shape, raw, endianness)
    end
  end

  # A field whose width the format fixes is checked against it. Reading a
  # four-byte drop count where the field is eight would not fail — it would
  # answer a number, and the wrong one, which is the drift two implementations of
  # one format are arranged to catch rather than to average out.
  @spec shaped(non_neg_integer(), non_neg_integer(), atom(), term(), binary(), :little | :big) ::
          {:ok, {atom(), term()}} | {:error, reason()}
  defp shaped(_type, _code, name, :text, raw, _endianness), do: {:ok, {name, raw}}

  defp shaped(_type, _code, name, {:uint, width}, raw, endianness)
       when byte_size(raw) == width,
       do: {:ok, {name, uint(raw, endianness)}}

  defp shaped(type, code, _name, {:uint, width}, raw, _endianness),
    do: {:error, {:option_length_unexpected, type, code, byte_size(raw), width}}

  defp shaped(_type, _code, name, :timestamp, <<high::binary-size(4), low::binary-size(4)>>, e),
    do: {:ok, {name, timestamp(high, low, e)}}

  defp shaped(type, code, _name, :timestamp, raw, _endianness),
    do: {:error, {:option_length_unexpected, type, code, byte_size(raw), 8}}

  defp shaped(_type, _code, name, :resolution, <<octet>>, _endianness),
    do: {:ok, {name, resolution(octet)}}

  defp shaped(type, code, _name, :resolution, raw, _endianness),
    do: {:error, {:option_length_unexpected, type, code, byte_size(raw), 1}}

  defp shaped(_type, _code, name, :verdict, <<kind, data::binary>>, _endianness),
    do: {:ok, {name, {kind, data}}}

  defp shaped(type, code, _name, :verdict, raw, _endianness),
    do: {:error, {:option_length_unexpected, type, code, byte_size(raw), 1}}

  defp shaped(_type, _code, name, :custom, <<pen::binary-size(4), data::binary>>, endianness),
    do: {:ok, {name, {uint(pen, endianness), data}}}

  defp shaped(type, code, _name, :custom, raw, _endianness),
    do: {:error, {:option_length_unexpected, type, code, byte_size(raw), 4}}

  # The high bit picks which of the octet's two meanings applies. Only the
  # decimal form is an appliance timestamp, and reading one form as the other
  # renders a plausible time wrong by orders of magnitude.
  @spec resolution(0..255) :: {:decimal, 0..127} | {:power_of_two, 0..127}
  defp resolution(octet) when octet < 0x80, do: {:decimal, octet}
  defp resolution(octet), do: {:power_of_two, octet - 0x80}

  @spec padding_for(non_neg_integer()) :: 0..3
  defp padding_for(length), do: rem(@alignment - rem(length, @alignment), @alignment)

  @spec zero?(binary()) :: boolean()
  defp zero?(bytes), do: bytes == <<0::size(byte_size(bytes) * 8)>>

  @spec uint(binary(), :little | :big) :: non_neg_integer()
  defp uint(bytes, endianness), do: :binary.decode_unsigned(bytes, endianness)

  @spec byte_order(binary()) :: {:ok, :little | :big} | {:error, reason()}
  defp byte_order(@magic_little), do: {:ok, :little}
  defp byte_order(@magic_big), do: {:ok, :big}
  defp byte_order(magic), do: {:error, {:bad_byte_order_magic, magic}}

  @spec hex(binary()) :: String.t()
  defp hex(bytes), do: "0x" <> Base.encode16(bytes, case: :lower)
end
