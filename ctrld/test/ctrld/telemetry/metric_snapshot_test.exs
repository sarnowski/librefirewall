defmodule Ctrld.Telemetry.MetricSnapshotTest do
  @moduledoc """
  The reader that turns a Custom Block into `metric_samples` rows.

  Its input is bytes out of a recording — a file that left a customer's
  premises — so every assertion here is about what arbitrary bytes do, and the
  readings it accepts are built from the same catalogue the appliance generated
  rather than from a table written out beside them.
  """

  use ExUnit.Case, async: true

  alias Ctrld.Telemetry.{MetricCatalogue, MetricSnapshot}

  @device String.duplicate("a", 32)

  # The block's own header, laid out as the contract states it.
  defp reading(options \\ []) do
    fingerprint = Keyword.get(options, :fingerprint, MetricCatalogue.fingerprint())
    slots = Keyword.get(options, :slots, MetricCatalogue.slots())
    instant = Keyword.get(options, :instant, 1_785_443_220_000_000_000)
    kind = Keyword.get(options, :kind, MetricSnapshot.kind())
    version = Keyword.get(options, :version, 1)
    reserved = Keyword.get(options, :reserved, <<0, 0>>)
    values = Keyword.get(options, :values, Enum.map(0..(slots - 1), &(&1 * 7 + 1)))

    body = for value <- values, into: <<>>, do: <<value::little-64>>

    <<kind, version, reserved::binary-size(2), fingerprint::little-32, instant::little-64,
      slots::little-32, body::binary>>
  end

  describe "the padding a recording is filled out with" do
    test "is answered as padding and never as a reading" do
      for data <- [<<>>, <<0>>, <<0::size(4096)-unit(8)>>] do
        assert MetricSnapshot.rows(@device, data) == {:error, :padding}
      end
    end

    test "reads as padding whatever length the recorder wrote it at" do
      for len <- [0, 1, 4, 16, 20, 512, 3748] do
        assert MetricSnapshot.rows(@device, <<0::size(len)-unit(8)>>) == {:error, :padding}
      end
    end
  end

  describe "a reading this build can map" do
    test "becomes one row per slot, in the catalogue's own order" do
      assert {:ok, %{rows: rows, unrepresentable: 0}} =
               MetricSnapshot.rows(@device, reading())

      assert length(rows) == MetricCatalogue.slots()

      [first | _] = rows
      {family, labels} = hd(MetricCatalogue.series())
      assert first.family == family
      assert first.labels == labels
      assert first.device_id == @device
      assert first.value == 1
    end

    test "carries the instant the appliance stamped it with, to microseconds" do
      assert {:ok, %{rows: [row | _]}} =
               MetricSnapshot.rows(@device, reading(instant: 1_785_443_220_123_456_789))

      assert row.observed_at == "2026-07-30 20:27:00.123456"
    end

    test "states the epoch where the appliance had no clock, rather than this server's time" do
      assert {:ok, %{rows: [row | _]}} = MetricSnapshot.rows(@device, reading(instant: 0))
      assert row.observed_at == "1970-01-01 00:00:00.000000"
    end

    test "every row names a family and a domain the catalogue declares" do
      assert {:ok, %{rows: rows}} = MetricSnapshot.rows(@device, reading())
      declared = MapSet.new(MetricCatalogue.series())

      for row <- rows do
        assert MapSet.member?(declared, {row.family, row.labels})
      end
    end
  end

  describe "a counter no Float64 holds exactly" do
    test "is refused by name rather than stored rounded" do
      slots = MetricCatalogue.slots()
      values = [9_007_199_254_740_993 | List.duplicate(1, slots - 1)]

      assert {:ok, %{rows: rows, unrepresentable: 1}} =
               MetricSnapshot.rows(@device, reading(values: values))

      assert length(rows) == slots - 1
      # And the slot it refused is gone rather than present under another value.
      {family, labels} = hd(MetricCatalogue.series())
      refute Enum.any?(rows, &(&1.family == family and &1.labels == labels))
    end

    test "the largest exactly representable counter is stored" do
      slots = MetricCatalogue.slots()
      values = [9_007_199_254_740_992 | List.duplicate(0, slots - 1)]

      assert {:ok, %{rows: [row | _], unrepresentable: 0}} =
               MetricSnapshot.rows(@device, reading(values: values))

      assert row.value == 9_007_199_254_740_992
    end
  end

  describe "a block this build will not map" do
    test "from another catalogue yields no rows at all" do
      foreign = MetricCatalogue.fingerprint() + 1

      assert {:error, {:foreign_catalogue, ^foreign, held}} =
               MetricSnapshot.rows(@device, reading(fingerprint: foreign))

      assert held == MetricCatalogue.fingerprint()
    end

    test "of another slot count is refused with both numbers" do
      assert {:error, {:slot_count_mismatch, 7, held}} =
               MetricSnapshot.rows(@device, reading(slots: 7, values: List.duplicate(1, 7)))

      assert held == MetricCatalogue.slots()
    end

    test "of another kind names the kind" do
      assert MetricSnapshot.rows(@device, reading(kind: 9)) == {:error, {:unknown_kind, 9}}
    end

    test "of another body version names the version" do
      assert MetricSnapshot.rows(@device, reading(version: 2)) ==
               {:error, {:unknown_version, 2}}
    end

    test "with a reserved byte set is refused" do
      assert MetricSnapshot.rows(@device, reading(reserved: <<1, 0>>)) ==
               {:error, :reserved_set}

      assert MetricSnapshot.rows(@device, reading(reserved: <<0, 1>>)) ==
               {:error, :reserved_set}
    end

    test "shorter than a header is refused with what arrived" do
      whole = reading()

      for len <- 1..19 do
        assert MetricSnapshot.rows(@device, binary_part(whole, 0, len)) ==
                 {:error, {:too_short, len}}
      end
    end

    test "cut short behind its header is refused rather than read as zeroes" do
      whole = reading()
      needed = byte_size(whole)

      for len <- [20, needed - 8, needed - 1] do
        assert {:error, {:truncated, ^len, ^needed}} =
                 MetricSnapshot.rows(@device, binary_part(whole, 0, len))
      end
    end
  end

  describe "the reader" do
    test "answers arbitrary bytes without raising" do
      for _ <- 1..200 do
        data = :crypto.strong_rand_bytes(:rand.uniform(64))

        case MetricSnapshot.rows(@device, data) do
          {:ok, %{rows: rows}} -> assert is_list(rows)
          {:error, refusal} -> assert is_atom(MetricSnapshot.tag(refusal))
        end
      end
    end

    test "answers a block whose leading byte is a reading over arbitrary bytes" do
      for _ <- 1..200 do
        tail = :crypto.strong_rand_bytes(:rand.uniform(64))
        data = <<MetricSnapshot.kind(), tail::binary>>

        case MetricSnapshot.rows(@device, data) do
          {:ok, %{rows: rows}} -> assert is_list(rows)
          {:error, refusal} -> assert is_binary(MetricSnapshot.describe(refusal))
        end
      end
    end

    test "reads only the slots the header names, never the padding behind them" do
      whole = reading()
      padded = whole <> <<0xFF::size(64)-unit(8)>>

      assert {:ok, %{rows: from_whole}} = MetricSnapshot.rows(@device, whole)
      assert {:ok, %{rows: from_padded}} = MetricSnapshot.rows(@device, padded)
      assert from_whole == from_padded
    end

    test "describes every refusal differently" do
      described =
        [
          :padding,
          {:unknown_kind, 3},
          {:unknown_version, 3},
          :reserved_set,
          {:too_short, 3},
          {:foreign_catalogue, 1, 2},
          {:slot_count_mismatch, 1, 2},
          {:truncated, 1, 2}
        ]
        |> Enum.map(&MetricSnapshot.describe/1)

      assert length(Enum.uniq(described)) == length(described)
    end
  end

  describe "the generated catalogue" do
    test "holds one entry per slot and a fingerprint" do
      assert length(MetricCatalogue.series()) == MetricCatalogue.slots()
      assert is_integer(MetricCatalogue.fingerprint())
      assert MetricCatalogue.slots() > 0
    end

    test "every entry carries a domain label the shard supplies" do
      for {family, labels} <- MetricCatalogue.series() do
        assert is_binary(family)
        assert is_binary(Map.fetch!(labels, "domain"))
      end
    end
  end
end
