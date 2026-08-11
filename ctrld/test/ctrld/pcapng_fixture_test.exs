defmodule Ctrld.PcapngFixtureTest do
  @moduledoc """
  The decoder against recordings the appliance's own encoder wrote.

  This is the test that makes the rest of them mean something. A decoder held
  only to bytes its own suite composed proves that one understanding of a format
  is self-consistent, which is not the property at issue: the format has two
  implementations in two languages in two components, and what has to be true is
  that this one reads what the other one writes. So the assertions below are
  about specific contents of specific recordings — the block sequence, the snap
  length each ring was configured with, a named interface, the length of a known
  frame, and the flow, rule and event annotating a known record.

  Every expectation here was read out of the appliance's encoder and confirmed
  against `tcpdump -r`, which opens all three files and renders the same
  instants this decoder resolves.
  """

  use ExUnit.Case, async: true

  alias Ctrld.Pcapng
  alias Ctrld.Pcapng.{Annotation, Custom, Interface, Packet, Section}
  alias Ctrld.RecordingFixtures

  # The IANA-reserved number the appliance tags its annotations with until one is
  # registered. Nobody's, deliberately, so a recording cannot escape claiming to
  # be somebody's.
  @unregistered_pen 0xFFFF_FFFF

  # The appliance's own verdict is none of the registered kinds, so it travels
  # under the vendor-defined one.
  @verdict_kind 0xFF

  describe "the log ring" do
    setup do: %{blocks: decode!("channel-established-logs")}

    test "opens a little-endian section naming the appliance and its annotation layout", %{
      blocks: [section | _]
    } do
      assert %Section{endianness: :little, major: 1, minor: 0, section_length: nil} = section

      assert section.options[:shb_os] == "librefirewall"
      assert section.options[:shb_userappl] == "librefirewall recorder"

      # The section states which annotation layout its records carry, so a reader
      # learns the schema from the file rather than from the appliance.
      assert section.options[:custom_binary] ==
               {@unregistered_pen, <<Annotation.version(), 0, 0, 0>>}
    end

    test "describes both dataplane ports as Ethernet at the log ring's snap length", %{
      blocks: [_section, first, second | _]
    } do
      assert %Interface{id: 0, link_type: 1, snap_len: 128, timestamp_digits: 6} = first
      assert %Interface{id: 1, link_type: 1, snap_len: 128, timestamp_digits: 6} = second

      assert first.options[:if_name] == "port0"
      assert second.options[:if_name] == "port1"
      assert first.options[:if_tsresol] == {:decimal, 6}
    end

    test "holds one record per direction of one conversation", %{blocks: blocks} do
      [inbound, outbound] = Enum.filter(blocks, &match?(%Packet{}, &1))

      # The log ring records a lifecycle event and the packet that caused it, so
      # the two records here are the two ends of one flow being opened.
      assert inbound.interface_id == 1
      assert outbound.interface_id == 0

      # Untruncated at this snap length: the frame was 65 bytes and 65 were kept.
      assert inbound.original_length == 65
      assert byte_size(inbound.data) == 65
      assert byte_size(outbound.data) == 65

      # The instant `tcpdump -r` renders for the first record of this file.
      assert inbound.observed_at == ~U[2026-08-10 22:56:45.043072Z]
      assert inbound.timestamp == 1_786_402_605_043_072

      # An Ethernet frame, which is what the interface said its frames are.
      assert <<0x52, 0x54, 0x00, 0x12, 0x34, 0x51, _::binary>> = inbound.data
    end

    test "states the tap lost nothing ahead of either record", %{blocks: blocks} do
      for %Packet{} = packet <- blocks do
        # The option is present and zero, which is a recording stating its own
        # loss rather than staying silent about it.
        assert packet.options[:epb_dropcount] == 0
      end
    end

    test "relates the two records by packet id", %{blocks: blocks} do
      [inbound, outbound] = Enum.filter(blocks, &match?(%Packet{}, &1))

      assert inbound.options[:epb_packetid] == 0
      assert outbound.options[:epb_packetid] == 5
    end

    test "annotates the opening record with its flow, rule and event", %{blocks: blocks} do
      [inbound | _] = Enum.filter(blocks, &match?(%Packet{}, &1))

      assert %Annotation{
               version: 3,
               verdict: 0,
               drop_reason: 0,
               interface_id: 1,
               direction: 0,
               classification: 1,
               event: 1,
               flow_state: 9,
               generation: 1,
               flow_slot: 0,
               flow_generation: 1,
               matched_rule: 2
             } = inbound.annotation

      # The verdict rides on the packet in its own option as well, under the
      # vendor kind, carrying the same decision the annotation states.
      assert inbound.options[:epb_verdict] == {@verdict_kind, <<0>>}

      # The raw option survives beside the decoded annotation, so an annotation
      # this build could not read would still be carried rather than lost.
      assert {@unregistered_pen, raw} = inbound.options[:custom_binary]
      assert byte_size(raw) == Annotation.length()
    end

    test "seals the segment with a zero-filled custom block every reader skips", %{blocks: blocks} do
      [custom] = Enum.filter(blocks, &match?(%Custom{}, &1))

      assert custom.pen == @unregistered_pen
      assert byte_size(custom.data) == 476
      assert custom.data == <<0::size(476 * 8)>>
    end

    test "accounts for every byte of the file", %{blocks: blocks} do
      assert Enum.count(blocks) == 6

      assert Enum.map(blocks, & &1.__struct__) == [
               Section,
               Interface,
               Interface,
               Packet,
               Packet,
               Custom
             ]
    end
  end

  describe "the capture ring" do
    setup do: %{blocks: decode!("channel-established-capture")}

    test "is the same shape at a snap length of its own", %{blocks: blocks} do
      interfaces = Enum.filter(blocks, &match?(%Interface{}, &1))

      assert Enum.count(interfaces) == 2

      for interface <- interfaces do
        # Depth rather than breadth: the capture keeps sixteen times the bytes
        # per frame the connection history does.
        assert interface.snap_len == 2048
      end
    end

    test "holds a record per observation rather than per event", %{blocks: blocks} do
      packets = Enum.filter(blocks, &match?(%Packet{}, &1))

      assert Enum.count(packets) == 31
      assert Enum.count(blocks) == 35

      # Every record carries a decoded annotation, so nothing in a real recording
      # falls through to the raw-option path.
      assert Enum.all?(packets, &match?(%Annotation{version: 3}, &1.annotation))
    end

    test "carries records in the order the appliance wrote them", %{blocks: blocks} do
      packets = Enum.filter(blocks, &match?(%Packet{}, &1))
      instants = Enum.map(packets, & &1.observed_at)

      assert instants == Enum.sort(instants, DateTime)
    end
  end

  describe "a policy revocation" do
    setup do: %{blocks: decode!("policy-revocation-logs")}

    test "carries all three verdicts the appliance can reach", %{blocks: blocks} do
      verdicts = for %Packet{annotation: %Annotation{verdict: v}} <- blocks, do: v

      assert Enum.sort(Enum.uniq(verdicts)) == [0, 1, 2]
    end

    test "records a revoked flow as an event about no frame at all", %{blocks: blocks} do
      packets = Enum.filter(blocks, &match?(%Packet{}, &1))
      revoked = Enum.find(packets, &(&1.annotation.verdict == 2))

      # A newly committed policy no longer admits a conversation it had admitted,
      # so the appliance took the flow back — and no packet caused that. The
      # record says so with an empty frame and a wire length of zero, which is
      # what tells a reader there was no packet rather than an empty one.
      assert revoked.data == <<>>
      assert revoked.original_length == 0
      assert revoked.options[:epb_verdict] == {@verdict_kind, <<2>>}

      # The event is the revocation, and it names the flow it was about while
      # carrying no classification, a classification being about a packet.
      assert revoked.annotation.event == 7
      assert revoked.annotation.classification == 0
      assert revoked.annotation.flow_slot == 1
      assert revoked.annotation.generation == 2
    end

    test "refuses the conversation's next packets under the new generation", %{blocks: blocks} do
      packets = Enum.filter(blocks, &match?(%Packet{}, &1))
      dropped = Enum.filter(packets, &(&1.annotation.verdict == 1))

      assert Enum.count(dropped) == 2

      for packet <- dropped do
        # No rule was about the opening packet, so the default deny refused it:
        # drop reason 26 with the matching event, and no rule named.
        assert packet.annotation.drop_reason == 26
        assert packet.annotation.event == 5
        assert packet.annotation.matched_rule == 0
        assert packet.annotation.generation == 2
      end

      # The flow slot was reused under a new occupant each time it was refused,
      # which is the reuse a bare slot index would have hidden.
      assert Enum.map(dropped, & &1.annotation.flow_generation) == [2, 3]
    end
  end

  describe "every fixture" do
    test "decodes whole, leaving nothing buffered and no unread trailing byte" do
      for name <- RecordingFixtures.names() do
        bytes = RecordingFixtures.read!(name)

        assert {:ok, blocks, decoder} = Pcapng.decode(Pcapng.new(), bytes)
        assert Pcapng.buffered(decoder) == 0, "#{name} left a partial block"

        # A recording opens on a section and, being a sealed ring segment, ends on
        # the padding block that filled the sector behind its last record.
        assert [%Section{} | _] = blocks
        assert %Custom{} = List.last(blocks)
      end
    end

    test "resolves every record's instant against its own interface" do
      for name <- RecordingFixtures.names() do
        {:ok, blocks, _} = Pcapng.decode(Pcapng.new(), RecordingFixtures.read!(name))

        for %Packet{} = packet <- blocks do
          # Microseconds, which is the resolution every interface in these files
          # declares, so the tick count and the instant hold the same number.
          assert DateTime.to_unix(packet.observed_at, :microsecond) == packet.timestamp
        end
      end
    end
  end

  defp decode!(name) do
    {:ok, blocks, decoder} = Pcapng.decode(Pcapng.new(), RecordingFixtures.read!(name))
    assert Pcapng.buffered(decoder) == 0
    blocks
  end
end
