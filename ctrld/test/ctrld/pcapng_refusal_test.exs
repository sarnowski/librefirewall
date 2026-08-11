defmodule Ctrld.PcapngRefusalTest do
  @moduledoc """
  Every way these bytes can be wrong, once each, by name.

  Each case starts from a recording the appliance actually wrote and breaks one
  field of it — a length, a trailer, an option's width, a padding byte. That is
  deliberate and not merely convenient: a blob assembled to fail proves that a
  refusal exists, while a real recording with one field broken proves it is the
  refusal that field earns, and that the twenty-odd others did not fire first.
  Two cases have no fixture to break, and each says why where it stands.

  Every refusal is also put through `describe/1`, because a reason with no
  clause there would raise inside the very path that exists to avoid raising —
  and an appliance is diagnosed from what an operator can read.
  """

  use ExUnit.Case, async: true

  alias Ctrld.Pcapng
  alias Ctrld.RecordingFixtures

  @section_header 0x0A0D_0D0A
  @option_header 4
  @interface_description 0x0000_0001
  @enhanced_packet 0x0000_0006

  describe "the framing" do
    test "a stream that does not open on a section header" do
      # An interface description is a legal block and still cannot open a stream:
      # nothing has said which byte order to read its fields in.
      bytes = RecordingFixtures.read!("channel-established-logs")
      {offset, total} = RecordingFixtures.block!(bytes, @interface_description)

      assert {:error, {:not_a_section_header, type} = reason} =
               Pcapng.decode(Pcapng.new(), binary_part(bytes, offset, total))

      assert type == <<0x01, 0x00, 0x00, 0x00>>
      assert described(reason) =~ "rather than on a section header"
    end

    test "a byte-order magic in neither orientation" do
      bytes = RecordingFixtures.read!("channel-established-logs")
      broken = RecordingFixtures.patch(bytes, 8, <<0xDE, 0xAD, 0xBE, 0xEF>>)

      assert {:error, {:bad_byte_order_magic, <<0xDE, 0xAD, 0xBE, 0xEF>>} = reason} =
               Pcapng.decode(Pcapng.new(), broken)

      # The bytes are rendered as hex rather than interpolated, so a peer cannot
      # put anything of its own choosing into a line an operator reads.
      assert described(reason) =~ "0xdeadbeef"
    end

    test "a major version whose block layouts this reader does not know" do
      bytes = RecordingFixtures.read!("channel-established-logs")
      broken = RecordingFixtures.patch(bytes, 12, <<2::unsigned-little-16>>)

      assert {:error, {:unsupported_section_version, 2, 0} = reason} =
               Pcapng.decode(Pcapng.new(), broken)

      assert described(reason) =~ "version 2.0"
    end

    test "a block type the appliance does not write" do
      bytes = RecordingFixtures.read!("channel-established-logs")
      {offset, _total} = RecordingFixtures.block!(bytes, @enhanced_packet)
      broken = RecordingFixtures.patch(bytes, offset, RecordingFixtures.u32(0x0000_0003))

      assert {:error, {:unknown_block_type, 3} = reason} = Pcapng.decode(Pcapng.new(), broken)
      assert described(reason) =~ "not one the appliance writes"
    end

    test "a length below what the block's own fields need" do
      bytes = RecordingFixtures.read!("channel-established-logs")
      {offset, _total} = RecordingFixtures.block!(bytes, @enhanced_packet)
      broken = RecordingFixtures.patch(bytes, offset + 4, RecordingFixtures.u32(16))

      assert {:error, {:block_too_short, @enhanced_packet, 16, 32} = reason} =
               Pcapng.decode(Pcapng.new(), broken)

      assert described(reason) =~ "below the 32"
    end

    test "a length past the bound this reader will buffer" do
      bytes = RecordingFixtures.read!("channel-established-logs")
      {offset, _total} = RecordingFixtures.block!(bytes, @enhanced_packet)
      absurd = Pcapng.max_block_bytes() + 4
      broken = RecordingFixtures.patch(bytes, offset + 4, RecordingFixtures.u32(absurd))

      # Refused on the number the peer stated, with none of the bytes it claims
      # in hand — which is what keeps a declared gigabyte from costing one.
      assert {:error, {:block_too_long, @enhanced_packet, ^absurd, bound} = reason} =
               Pcapng.decode(Pcapng.new(), binary_part(broken, 0, offset + 8))

      assert bound == Pcapng.max_block_bytes()
      assert described(reason) =~ "past this reader's bound"
    end

    test "a length that is not a multiple of four" do
      bytes = RecordingFixtures.read!("channel-established-logs")
      {offset, total} = RecordingFixtures.block!(bytes, @enhanced_packet)
      broken = RecordingFixtures.patch(bytes, offset + 4, RecordingFixtures.u32(total + 1))

      assert {:error, {:block_length_not_aligned, @enhanced_packet, _} = reason} =
               Pcapng.decode(Pcapng.new(), broken)

      assert described(reason) =~ "not a multiple of 4"
    end

    test "a trailer that disagrees with the length the block opened on" do
      bytes = RecordingFixtures.read!("channel-established-logs")
      {offset, total} = RecordingFixtures.block!(bytes, @enhanced_packet)

      broken =
        RecordingFixtures.patch(bytes, offset + total - 4, RecordingFixtures.u32(total + 4))

      # The one corruption that would otherwise leave every later block at an
      # offset no reader can find.
      assert {:error, {:length_trailer_mismatch, @enhanced_packet, ^total, trailer} = reason} =
               Pcapng.decode(Pcapng.new(), broken)

      assert trailer == total + 4
      assert described(reason) =~ "closes on"
    end

    test "a trailer that matches only when read in the other byte order" do
      bytes = RecordingFixtures.read!("channel-established-logs")
      {offset, total} = RecordingFixtures.block!(bytes, @enhanced_packet)
      reversed = <<total::unsigned-big-32>>
      broken = RecordingFixtures.patch(bytes, offset + total - 4, reversed)

      # A section states one byte order and both its length fields are in it. A
      # trailer that agrees only reversed is a disagreement, not a dialect.
      assert {:error, {:length_trailer_mismatch, @enhanced_packet, ^total, _}} =
               Pcapng.decode(Pcapng.new(), broken)
    end
  end

  describe "a record's payload" do
    test "a captured length past the room its block has" do
      bytes = RecordingFixtures.read!("channel-established-logs")
      {offset, _total} = RecordingFixtures.block!(bytes, @enhanced_packet)
      broken = RecordingFixtures.patch(bytes, offset + 8 + 12, RecordingFixtures.u32(4096))

      assert {:error, {:packet_exceeds_block, 4096, available} = reason} =
               Pcapng.decode(Pcapng.new(), broken)

      assert is_integer(available) and available < 4096
      assert described(reason) =~ "captured bytes with"
    end

    test "more captured bytes than the frame had on the wire" do
      bytes = RecordingFixtures.read!("channel-established-logs")
      {offset, _total} = RecordingFixtures.block!(bytes, @enhanced_packet)

      # The frame was 65 bytes; saying it was 8 on the wire describes a packet
      # that grew in transit, which the encoder refuses to write in the first place.
      broken = RecordingFixtures.patch(bytes, offset + 8 + 16, RecordingFixtures.u32(8))

      assert {:error, {:captured_exceeds_original, 65, 8} = reason} =
               Pcapng.decode(Pcapng.new(), broken)

      assert described(reason) =~ "of a frame that was 8 on the wire"
    end

    test "payload padding that is not zero" do
      bytes = RecordingFixtures.read!("channel-established-logs")
      {offset, _total} = RecordingFixtures.block!(bytes, @enhanced_packet)

      # The 65-byte frame is padded with three zero bytes. Anything else there is
      # the ring bleeding through what it held before this record was placed.
      broken = RecordingFixtures.patch(bytes, offset + 8 + 20 + 65, <<0xFF>>)

      assert {:error, {:payload_padding_not_zero, @enhanced_packet} = reason} =
               Pcapng.decode(Pcapng.new(), broken)

      assert described(reason) =~ "not zero"
    end
  end

  describe "an option list" do
    test "an option stating more bytes than its block holds" do
      bytes = RecordingFixtures.read!("channel-established-logs")
      {offset, _total} = RecordingFixtures.block!(bytes, @enhanced_packet)
      at = RecordingFixtures.packet_options_at(bytes, offset)
      broken = RecordingFixtures.patch(bytes, at + 2, <<512::unsigned-little-16>>)

      assert {:error, {:truncated_option, @enhanced_packet, 2, 512} = reason} =
               Pcapng.decode(Pcapng.new(), broken)

      assert described(reason) =~ "the block ends"
    end

    test "an option area ending without its terminator" do
      bytes = RecordingFixtures.read!("channel-established-logs")
      {offset, total} = RecordingFixtures.block!(bytes, @enhanced_packet)

      # The terminator is the last four bytes before the trailer. Turning it into
      # a further option consumes the area without ever closing it.
      broken =
        RecordingFixtures.patch(bytes, offset + total - 8, <<9::unsigned-little-16, 0::16>>)

      assert {:error, {:unterminated_options, @enhanced_packet} = reason} =
               Pcapng.decode(Pcapng.new(), broken)

      assert described(reason) =~ "without a terminator"
    end

    test "bytes behind the terminator" do
      bytes = RecordingFixtures.read!("channel-established-logs")
      {offset, total} = RecordingFixtures.block!(bytes, @enhanced_packet)

      # Moving the terminator earlier leaves the option it displaced behind it,
      # which this reader cannot account for and will not step over.
      at = RecordingFixtures.packet_options_at(bytes, offset)
      broken = RecordingFixtures.patch(bytes, at, <<0::16, 0::16>>)

      assert {:error, {:trailing_option_bytes, @enhanced_packet, count} = reason} =
               Pcapng.decode(Pcapng.new(), broken)

      assert count == offset + total - 4 - (at + 4)
      assert described(reason) =~ "follow the option terminator"
    end

    test "a terminator carrying a length" do
      bytes = RecordingFixtures.read!("channel-established-logs")
      {offset, total} = RecordingFixtures.block!(bytes, @enhanced_packet)
      broken = RecordingFixtures.patch(bytes, offset + total - 6, <<4::unsigned-little-16>>)

      assert {:error, {:option_terminator_not_empty, 4} = reason} =
               Pcapng.decode(Pcapng.new(), broken)

      assert described(reason) =~ "carries none"
    end

    test "option padding that is not zero" do
      bytes = RecordingFixtures.read!("channel-established-logs")
      {offset, _total} = RecordingFixtures.block!(bytes, @interface_description)

      # The interface's resolution option is one byte followed by three of
      # padding, which the encoder writes as zero.
      at = RecordingFixtures.options_at(offset, 8)
      resolution = at + @option_header + padded("port0")

      assert <<9::unsigned-little-16, 1::unsigned-little-16, 6>> =
               binary_part(bytes, resolution, 5)

      broken = RecordingFixtures.patch(bytes, resolution + @option_header + 1, <<0xFF>>)

      assert {:error, {:option_padding_not_zero, @interface_description, 9} = reason} =
               Pcapng.decode(Pcapng.new(), broken)

      assert described(reason) =~ "not zero"
    end

    test "a fixed-width field carrying the wrong number of bytes" do
      bytes = RecordingFixtures.read!("channel-established-logs")
      {offset, _total} = RecordingFixtures.block!(bytes, @enhanced_packet)
      at = RecordingFixtures.packet_options_at(bytes, offset)

      # The drop count is eight octets. Read as four it would not fail — it would
      # answer a number, and the wrong one, which is the drift this refusal is for.
      drop_count = at + 4 + 4

      assert <<4::unsigned-little-16, 8::unsigned-little-16>> = binary_part(bytes, drop_count, 4)

      broken =
        RecordingFixtures.patch(
          bytes,
          drop_count,
          <<4::unsigned-little-16, 4::unsigned-little-16>>
        )

      assert {:error, {:option_length_unexpected, @enhanced_packet, 4, 4, 8} = reason} =
               Pcapng.decode(Pcapng.new(), broken)

      assert described(reason) =~ "where its field is 8"
    end
  end

  describe "a timestamp" do
    test "a resolution stated in the power-of-two form" do
      bytes = RecordingFixtures.read!("channel-established-logs")
      {offset, _total} = RecordingFixtures.block!(bytes, @interface_description)
      at = RecordingFixtures.options_at(offset, 8)
      octet = at + @option_header + padded("port0") + @option_header

      # The octet's high bit picks its meaning, and reading one form as the other
      # renders a plausible time that is wrong by orders of magnitude.
      broken = RecordingFixtures.patch(bytes, octet, <<0x80 + 20>>)

      assert {:error, {:unsupported_timestamp_resolution, 148} = reason} =
               Pcapng.decode(Pcapng.new(), broken)

      assert described(reason) =~ "power-of-two"
    end

    test "a tick count that is not an instant" do
      bytes = RecordingFixtures.read!("channel-established-logs")
      {offset, _total} = RecordingFixtures.block!(bytes, @enhanced_packet)

      # The high half of the timestamp, taken to all ones: microseconds beyond
      # any year a calendar has.
      broken = RecordingFixtures.patch(bytes, offset + 8 + 4, RecordingFixtures.u32(0xFFFF_FFFF))

      assert {:error, {:timestamp_out_of_range, _ticks} = reason} =
               Pcapng.decode(Pcapng.new(), broken)

      assert described(reason) =~ "is not an instant"
    end

    test "a record naming an interface its section never described" do
      bytes = RecordingFixtures.read!("channel-established-logs")
      {offset, _total} = RecordingFixtures.block!(bytes, @enhanced_packet)

      # This section describes two ports. A record about a seventh has no
      # resolution to read its ticks in, and so no instant to be stored under.
      broken = RecordingFixtures.patch(bytes, offset + 8, RecordingFixtures.u32(7))

      assert {:error, {:unknown_interface, 7} = reason} = Pcapng.decode(Pcapng.new(), broken)
      assert described(reason) =~ "never described"
    end
  end

  describe "a section describing too many interfaces" do
    test "is refused past the bound this reader holds" do
      # No recording to break here: the appliance's schema admits eight ports and
      # this bound is well above that, so the only way to reach it is to repeat a
      # real interface description until it is crossed.
      bytes = RecordingFixtures.read!("channel-established-logs")
      {section_at, section_total} = RecordingFixtures.block!(bytes, @section_header)
      {interface_at, interface_total} = RecordingFixtures.block!(bytes, @interface_description)

      section = binary_part(bytes, section_at, section_total)
      interface = binary_part(bytes, interface_at, interface_total)
      bound = Pcapng.max_interfaces()

      assert {:error, {:too_many_interfaces, ^bound} = reason} =
               Pcapng.decode(
                 Pcapng.new(),
                 section <> String.duplicate(interface, bound + 1)
               )

      assert described(reason) =~ "more than the #{bound}"
    end
  end

  describe "a refusal" do
    test "ends the stream rather than carrying a state to continue from" do
      bytes = RecordingFixtures.read!("channel-established-logs")
      {offset, total} = RecordingFixtures.block!(bytes, @enhanced_packet)

      broken =
        RecordingFixtures.patch(bytes, offset + total - 4, RecordingFixtures.u32(total + 4))

      # Two elements, never three: there is no decoder in a refusal, because the
      # offset of the block after this one is no longer known.
      assert {:error, reason} = Pcapng.decode(Pcapng.new(), broken)
      assert tuple_size(reason) >= 1
    end
  end

  defp described(reason) do
    description = Pcapng.describe(reason)
    assert is_binary(description) and description != ""
    description
  end

  defp padded(value) do
    size = byte_size(value)
    size + rem(4 - rem(size, 4), 4)
  end
end
