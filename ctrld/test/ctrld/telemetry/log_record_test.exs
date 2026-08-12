defmodule Ctrld.Telemetry.LogRecordTest do
  @moduledoc """
  The reader that turns a Custom Block into `log_events` rows.

  Its input is bytes out of a recording — a file that left a customer's
  premises — so every assertion here is about what arbitrary bytes do, and the
  vocabulary a line's origin is read through is the one the appliance generated
  rather than a list written out beside it.
  """

  use ExUnit.Case, async: true

  alias Ctrld.Telemetry.LogRecord

  @device String.duplicate("a", 32)

  @ready "LFW-PD time=2026-07-30T20:27:00.000000000Z domain=recorder state=ready"
  @refused "LFW-PD time=unsynchronized domain=store state=refused cause=package-refused"
  @applied "LFW-CFG time=unsynchronized generation=1 outcome=applied changes=16"

  # One entry, laid out as the contract states it.
  defp entry(options) do
    origin = Keyword.get(options, :origin, 0)
    line = Keyword.get(options, :line, @ready)
    instant = Keyword.get(options, :instant)
    flags = Keyword.get(options, :flags, if(instant, do: 1, else: 0))
    len = Keyword.get(options, :len, byte_size(line))

    <<origin, flags, len::little-16, instant || 0::little-64, line::binary>>
  end

  # The block's own header and the entries behind it.
  defp batch(entries, options \\ []) do
    kind = Keyword.get(options, :kind, LogRecord.kind())
    version = Keyword.get(options, :version, 1)
    reserved = Keyword.get(options, :reserved, <<0, 0>>)
    tail_reserved = Keyword.get(options, :tail_reserved, <<0, 0>>)
    count = Keyword.get(options, :count, length(entries))
    body = Enum.join(entries)

    <<kind, version, reserved::binary-size(2), count::little-16, tail_reserved::binary-size(2),
      body::binary>>
  end

  describe "the two other things a custom block of this enterprise number carries" do
    test "padding is answered as padding and never as a transcript" do
      for data <- [<<>>, <<0>>, <<0::size(4096)-unit(8)>>] do
        assert LogRecord.rows(@device, data) == {:error, :padding}
      end
    end

    test "a metric reading is named as one rather than as an unknown kind" do
      assert LogRecord.rows(@device, <<1, 1, 0, 0, 0::size(64)-unit(8)>>) ==
               {:error, :metric_reading}
    end

    test "and a kind neither reader knows is refused by its number" do
      assert LogRecord.rows(@device, <<7, 1, 0, 0>>) == {:error, {:unknown_kind, 7}}
    end
  end

  describe "a batch this appliance wrote" do
    test "becomes one row per line, in the order they were printed" do
      data =
        batch([
          entry(origin: 6, instant: 1_785_443_220_000_000_000, line: @ready),
          entry(origin: 9, line: @refused),
          entry(origin: 2, line: @applied)
        ])

      assert {:ok, %{rows: [first, second, third], refused: 0}} =
               LogRecord.rows(@device, data)

      assert first.device_id == @device
      assert first.domain == "recorder"
      assert first.severity == "ready"
      assert first.event == "domain"
      assert first.detail == @ready
      assert first.observed_at == "2026-07-30 20:27:00.000000"

      assert second.domain == "store"
      assert second.severity == "refused"
      assert second.detail == @refused

      assert third.domain == "config"
      assert third.event == "config-generation"
      assert third.severity == "", "a configuration record carries no lifecycle state"
    end

    test "stores the line byte for byte, because the line is the record" do
      widest = String.duplicate("~", 256)
      data = batch([entry(line: widest)])
      assert {:ok, %{rows: [row]}} = LogRecord.rows(@device, data)
      assert row.detail == widest
    end

    test "names the domain the console drained it from and not the token in the line" do
      # A record claiming to be the store, out of the nic-driver's ring. The
      # appliance's topology decides the ring and no writing domain can forge it;
      # the token in the line is that domain's own claim.
      data = batch([entry(origin: 1, line: @refused)])
      assert {:ok, %{rows: [row]}} = LogRecord.rows(@device, data)
      assert row.domain == "nic-driver"
      assert row.detail =~ "domain=store"
    end

    test "carries an empty batch as no rows rather than as a refusal" do
      assert LogRecord.rows(@device, batch([])) == {:ok, %{rows: [], refused: 0}}
    end

    test "distinguishes the three configuration shapes" do
      shapes = [
        {"LFW-CFG time=x generation=1 seq=0 change=added object=rule key=a field=action",
         "config-change"},
        {"LFW-CFG time=x generation=1 outcome=applied changes=2", "config-generation"},
        {"LFW-CFG time=x generation=1 rejected=unknown-field offset=12", "config-rejected"}
      ]

      for {line, event} <- shapes do
        assert {:ok, %{rows: [row]}} = LogRecord.rows(@device, batch([entry(line: line)]))
        assert row.event == event, line
      end
    end
  end

  describe "a line the appliance emitted before it had a clock" do
    test "is stored at the epoch rather than at this server's own time" do
      data = batch([entry(line: @refused)])
      assert {:ok, %{rows: [row]}} = LogRecord.rows(@device, data)
      assert row.observed_at == "1970-01-01 00:00:00.000000"
      assert row.detail =~ "time=unsynchronized", "and the line still says so"
    end

    test "which is not the same as an instant that happens to be zero" do
      # The flag is what tells them apart, so a stamped zero is the epoch stated
      # rather than the absence of a statement — and both land in the same column,
      # which is exactly why the line beside it matters.
      stamped = batch([entry(instant: 0, line: @ready)])
      assert {:ok, %{rows: [row]}} = LogRecord.rows(@device, stamped)
      assert row.observed_at == "1970-01-01 00:00:00.000000"
    end
  end

  describe "a block this build will not read" do
    test "a body version it does not know is refused by name" do
      data = batch([entry([])], version: 2)
      assert LogRecord.rows(@device, data) == {:error, {:unknown_version, 2}}
    end

    test "a reserved byte that is not zero is a writer it shares no layout with" do
      for options <- [[reserved: <<1, 0>>], [tail_reserved: <<0, 1>>]] do
        data = batch([entry([])], options)
        assert LogRecord.rows(@device, data) == {:error, :reserved_set}, inspect(options)
      end
    end

    test "a header cut short is refused rather than read past" do
      whole = batch([entry([])])

      for len <- 1..7 do
        assert LogRecord.rows(@device, binary_part(whole, 0, len)) ==
                 {:error, {:too_short, len}}
      end
    end

    test "a flag bit it does not define is refused by name" do
      data = batch([entry(flags: 0x80)])
      assert LogRecord.rows(@device, data) == {:error, {:unknown_flags, 0, 0x80}}
    end

    test "a stated length that runs past the bytes behind it is refused as truncated" do
      data = batch([entry(len: 512)])
      assert LogRecord.rows(@device, data) == {:error, {:truncated, 0}}
    end

    test "and a count no writer produced runs out of bytes rather than looping" do
      data = batch([entry([])], count: 4_000)
      assert LogRecord.rows(@device, data) == {:error, {:truncated, 1}}
    end
  end

  describe "the lines already read stand when a later one does not" do
    test "because what was whole was printed" do
      data = batch([entry(line: @ready), entry(len: 999)])
      assert LogRecord.rows(@device, data) == {:error, {:truncated, 1}}
    end
  end

  describe "text no protection domain printed" do
    test "is refused rather than stored, whichever byte gives it away" do
      # A relay slot the console never reached is zeroes, and one read while it was
      # being written is two lines spliced. Both leave the console's alphabet.
      for byte <- [0, 0x09, 0x0A, 0x0D, 0x1F, 0x7F, 0x80, 0xFF] do
        line = "LFW-PD dom" <> <<byte>> <> "in=store state=ready"
        data = batch([entry(line: line)])

        assert LogRecord.rows(@device, data) == {:error, {:unprintable, 0}},
               "byte #{byte} was stored"
      end
    end

    test "and every byte the console grammar can render crosses" do
      line = for byte <- 0x20..0x7E, into: <<>>, do: <<byte>>
      assert {:ok, %{rows: [row]}} = LogRecord.rows(@device, batch([entry(line: line)]))
      assert row.detail == line
    end
  end

  describe "a line from a ring this server cannot name" do
    test "yields no row and is counted, because a wrong domain is worse than none" do
      data = batch([entry(origin: 0, line: @ready), entry(origin: 200, line: @ready)])
      assert {:ok, %{rows: rows, refused: 1}} = LogRecord.rows(@device, data)
      assert length(rows) == 1
    end
  end

  describe "the vocabulary the origin byte indexes" do
    test "is the appliance's own, generated rather than restated here" do
      domains = LogRecord.domains()
      assert "forwarder" in domains
      assert "recorder" in domains
      assert "console" in domains
      assert length(domains) == length(Enum.uniq(domains))
    end
  end

  describe "arbitrary bytes" do
    test "are a batch or a named refusal, and never a crash" do
      for _ <- 1..3_000 do
        data = :crypto.strong_rand_bytes(:rand.uniform(128))

        case LogRecord.rows(@device, data) do
          {:ok, %{rows: rows}} -> assert is_list(rows)
          {:error, refusal} -> assert is_atom(LogRecord.tag(refusal))
        end
      end
    end

    test "behind a header this build accepts, too" do
      for _ <- 1..3_000 do
        body = :crypto.strong_rand_bytes(:rand.uniform(96))
        count = :rand.uniform(20) - 1
        data = <<LogRecord.kind(), 1, 0, 0, count::little-16, 0, 0, body::binary>>

        case LogRecord.rows(@device, data) do
          {:ok, %{rows: rows}} -> assert is_list(rows)
          {:error, refusal} -> assert is_atom(LogRecord.tag(refusal))
        end
      end
    end
  end

  describe "every refusal" do
    test "reads as a sentence naming its own cause" do
      refusals = [
        :padding,
        :metric_reading,
        {:unknown_kind, 7},
        {:unknown_version, 2},
        :reserved_set,
        {:too_short, 3},
        {:truncated, 1},
        {:unknown_flags, 0, 0x80},
        {:unprintable, 2},
        {:unknown_origin, 200}
      ]

      sentences = Enum.map(refusals, &LogRecord.describe/1)
      assert Enum.all?(sentences, &(String.length(&1) > 10))
      assert length(Enum.uniq(sentences)) == length(sentences)
    end
  end
end
