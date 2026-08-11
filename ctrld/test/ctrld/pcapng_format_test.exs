defmodule Ctrld.PcapngFormatTest do
  @moduledoc """
  The two shapes the format has and no recording contains.

  Everywhere else this decoder is held to bytes the appliance wrote, because that
  is the only evidence that two implementations of one format still agree. These
  two cases have no such bytes to be held to, and both are here rather than left
  untested because the reason each is absent could stop being true without this
  side changing at all:

  An **Interface Statistics Block** is a block the appliance's encoder can write
  and its recorder does not — a recording states its loss through each record's
  drop count instead. A producer appearing over there must not be the moment this
  server starts refusing streams.

  A **big-endian section** cannot be produced by an appliance at all: it runs on
  one architecture and writes the byte-order magic rather than choosing it. What
  is under test is therefore the format's rule — that a section states which
  order it used and a reader takes it from there — rather than any habit of the
  writer's. Reading the magic instead of assuming it is what makes that rule
  hold, and this is the only test that can tell the two apart.

  Both are built from the encoder's own layout, and both say what that layout is
  where they build it.
  """

  use ExUnit.Case, async: true

  alias Ctrld.Pcapng
  alias Ctrld.Pcapng.{Interface, Packet, Section, Statistics}
  alias Ctrld.RecordingFixtures

  describe "an interface statistics block" do
    test "decodes its instant and its four counts" do
      assert {:ok, blocks, decoder} =
               Pcapng.decode(Pcapng.new(), RecordingFixtures.statistics_stream())

      assert Pcapng.buffered(decoder) == 0
      assert [%Section{}, %Interface{}, %Statistics{} = statistics] = blocks

      assert statistics.interface_id == 0
      assert statistics.timestamp == 1_700_000_000_000_000
      assert statistics.observed_at == DateTime.from_unix!(1_700_000_000_000_000, :microsecond)

      # The two times are the format's pair of 32-bit halves rather than plain
      # 64-bit numbers, and reading one as the other would put it roughly four
      # billion seconds away.
      assert statistics.options[:isb_starttime] == 1_600_000_000_000_000
      assert statistics.options[:isb_endtime] == 1_700_000_000_000_000

      # The counts are plain 64-bit numbers, which is the distinction the encoder
      # draws between a time and a total in the very same block.
      assert statistics.options[:isb_ifrecv] == 4321
      assert statistics.options[:isb_ifdrop] == 7
    end
  end

  describe "a big-endian section" do
    test "is read in the order its header declares" do
      assert {:ok, blocks, decoder} =
               Pcapng.decode(Pcapng.new(), RecordingFixtures.big_endian_stream())

      assert Pcapng.buffered(decoder) == 0
      assert [section, interface, packet] = blocks

      # The byte order is a fact about the section, and it is carried out so a
      # later reader never has to work it out a second time.
      assert %Section{endianness: :big, major: 1, minor: 0, section_length: nil} = section

      # Every field of every block that follows is read in that order — the
      # block's own type and length, the interface's link type and snap length,
      # and the record's lengths, timestamp halves and option widths alike.
      assert %Interface{id: 0, link_type: 1, snap_len: 128, timestamp_digits: 6} = interface
      assert %Packet{interface_id: 0, original_length: 5} = packet
      assert packet.data == <<0xAA, 0xBB, 0xCC, 0xDD, 0xEE>>
      assert packet.observed_at == RecordingFixtures.big_endian_observed_at()
      assert packet.options[:epb_dropcount] == RecordingFixtures.big_endian_drop_count()
    end

    test "cut at every offset, yields what the whole of it does" do
      bytes = RecordingFixtures.big_endian_stream()
      {:ok, expected, _} = Pcapng.decode(Pcapng.new(), bytes)

      for split <- 0..byte_size(bytes) do
        <<head::binary-size(^split), tail::binary>> = bytes

        assert {:ok, first, decoder} = Pcapng.decode(Pcapng.new(), head)
        assert {:ok, second, decoder} = Pcapng.decode(decoder, tail)
        assert first ++ second == expected, "cut at #{split} decoded differently"
        assert Pcapng.buffered(decoder) == 0
      end
    end
  end

  describe "a section with no options" do
    test "is complete rather than unterminated" do
      # The encoder writes no option area at all where there is no option to put
      # in it — not even a terminator — so an empty area has to be read as done.
      # The section above carries none, which every recording's does carry.
      bytes = RecordingFixtures.big_endian_stream()

      assert {:ok, [%Section{options: []} | _], _} = Pcapng.decode(Pcapng.new(), bytes)
    end
  end
end
