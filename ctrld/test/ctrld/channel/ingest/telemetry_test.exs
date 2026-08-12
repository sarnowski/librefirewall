defmodule Ctrld.Channel.Ingest.TelemetryTest do
  @moduledoc """
  The whole path, end to end: ring bytes an appliance really shipped, decoded,
  turned into rows, written to a real ClickHouse, and read back out of it.

  Nothing here is a stand-in. The bytes are the committed recordings the
  appliance's own encoder wrote, the store is the pinned ClickHouse the gate
  brings up — the suite refuses to start without one — and every assertion is
  on a row selected back rather than on a value this test handed over. Rows are
  keyed by a device identifier minted per test, so the one shared schema cannot
  let a test see another's.

  It is not asynchronous because the ingest holds state per appliance and ring
  in a process of its own, reachable by name, and reads its cursor out of the
  sandbox connection this test owns.
  """

  use Ctrld.DataCase, async: false

  alias Ctrld.Channel.Ingest
  alias Ctrld.Channel.Ingest.Telemetry
  alias Ctrld.Channel.Ingest.Telemetry.Ring
  alias Ctrld.RecordingFixtures
  alias Ctrld.Telemetry.{Cursor, MetricCatalogue, Store}

  # How many records each committed recording holds, counted here so a fixture
  # that changed shows up as a disagreement rather than as a silently smaller
  # assertion.
  @revocation_records 7
  @established_records 2

  setup do
    handler = {__MODULE__, System.unique_integer([:positive])}

    :telemetry.attach_many(
      handler,
      Telemetry.events(),
      fn event, measurements, metadata, test ->
        send(test, {:telemetry, List.last(event), measurements, metadata})
      end,
      self()
    )

    on_exit(fn -> :telemetry.detach(handler) end)

    %{device: device_id()}
  end

  describe "the configured ingest" do
    test "is the counting one in the suite, so no test gets one it did not ask for" do
      assert Ingest.configured() == Ctrld.Channel.Ingest.Counting
    end

    test "answers the seam with :ok and nothing else", %{device: device} do
      assert Telemetry.ring_bytes(device, :log, 0, RecordingFixtures.read!(name())) == :ok
      assert Telemetry.flush(device, :log) == :ok
    end

    test "has nothing to flush for a ring nothing has shipped to", %{device: device} do
      assert Telemetry.flush(device, :log) == :ok
    end
  end

  describe "a recording the appliance shipped" do
    test "lands in ClickHouse as the flows it records", %{device: device} do
      ship(device, :log, RecordingFixtures.read!(name()))

      rows = flow_events(device)
      assert length(rows) == @revocation_records

      opened = hd(rows)
      assert opened["observed_at"] == "2026-08-10 22:51:46.044152"
      assert opened["verdict"] == "forwarded"
      assert opened["event"] == "flow-opened"
      assert opened["flow_class"] == "new"
      assert opened["source_address"] == "10.0.0.2"
      assert opened["destination_address"] == "10.0.1.2"
      assert opened["source_port"] == 4444
      assert opened["destination_port"] == 5000
      assert opened["protocol"] == 17
      assert opened["matched_rule"] == 2
      assert opened["direction"] == "inbound"
      assert opened["generation"] == 1
    end

    test "goes in as the appliance's own codes and reads back as the names", %{device: device} do
      # This is what says the enumerated columns are written in a form the store
      # takes: the rows carried integers, and every one of them came back as the
      # member the schema declares for it. A code the store had not accepted
      # would have failed the whole batch rather than arriving as a name.
      ship(device, :log, RecordingFixtures.read!(name()))

      verdicts = flow_events(device) |> Enum.map(& &1["verdict"]) |> Enum.uniq() |> Enum.sort()
      assert verdicts == ["dropped", "forwarded", "revoked"]

      events = flow_events(device) |> Enum.map(& &1["event"]) |> Enum.uniq() |> Enum.sort()
      assert events == ["flow-advanced", "flow-opened", "flow-revoked", "policy-no-match"]
    end

    test "keeps the refusal a policy made, with the reason it made it", %{device: device} do
      ship(device, :log, RecordingFixtures.read!(name()))

      refused = Enum.find(flow_events(device), &(&1["verdict"] == "dropped"))

      assert refused["event"] == "policy-no-match"
      assert refused["drop_reason"] == 26
      assert refused["generation"] == 2
      assert refused["source_port"] == 5000
      assert refused["destination_port"] == 4445
    end

    test "keeps the revocation, which is about a flow and not a frame", %{device: device} do
      ship(device, :log, RecordingFixtures.read!(name()))

      revoked = Enum.find(flow_events(device), &(&1["verdict"] == "revoked"))

      assert revoked["event"] == "flow-revoked"
      assert revoked["flow_slot"] == 1
      assert revoked["observed_at"] == "2026-08-10 22:51:48.738213"

      # The one row shape that says the frame could not be read, and it cannot
      # be mistaken for a conversation: no IPv4 datagram carries protocol 0, so
      # this is exactly the set of rows with nothing to say about whom.
      assert revoked["protocol"] == 0
      assert revoked["source_address"] == "0.0.0.0"
      assert revoked["destination_address"] == "0.0.0.0"
      assert revoked["source_port"] == 0
      assert revoked["destination_port"] == 0
    end

    test "is the only row in that shape, every other frame having been read", %{device: device} do
      ship(device, :log, RecordingFixtures.read!(name()))

      unread = Enum.filter(flow_events(device), &(&1["protocol"] == 0))

      assert length(unread) == 1
      assert_received {:telemetry, :frame_unread, %{records: 1}, %{refusal: :no_frame}}
    end

    test "says how many rows it built and how many it wrote", %{device: device} do
      ship(device, :log, RecordingFixtures.read!(name()))

      assert_received {:telemetry, :rows_built, %{rows: @revocation_records}, %{ring: :log}}
      assert_received {:telemetry, :rows_inserted, %{rows: @revocation_records}, %{ring: :log}}
    end
  end

  describe "delivery is at-least-once, so the same bytes twice" do
    test "do not become the same rows twice", %{device: device} do
      bytes = RecordingFixtures.read!(name())

      ship(device, :log, bytes)
      first = flow_events(device)
      assert length(first) == @revocation_records

      # Exactly what a reconnect does: the ring from its beginning, again.
      ship(device, :log, bytes)

      assert flow_events(device) == first
      assert_received {:telemetry, :records_skipped, _measurements, %{cause: :already_stored}}
    end

    test "advance the durable cursor only as far as a whole block", %{device: device} do
      bytes = RecordingFixtures.read!(name())
      ship(device, :log, bytes)

      # The fixture is a whole recording, so every block in it is complete and
      # the cursor is the end of the last one.
      assert Cursor.position(device, :log) == byte_size(bytes)
    end

    test "leave the cursor alone where nothing was stored", %{device: device} do
      assert Cursor.position(device, :log) == 0
      ship(device, :capture, RecordingFixtures.read!("channel-established-capture"))
      assert Cursor.position(device, :capture) == 0
    end
  end

  describe "a shipment cut into pieces" do
    test "produces exactly the rows one whole delivery does", %{device: device} do
      whole = device_id()
      bytes = RecordingFixtures.read!(name())

      ship(whole, :log, bytes)
      split(device, :log, bytes, 97)

      assert comparable(flow_events(device)) == comparable(flow_events(whole))
      assert length(flow_events(device)) == @revocation_records
    end

    test "produces them for a piece size that cuts every block", %{device: device} do
      bytes = RecordingFixtures.read!(name())
      split(device, :log, bytes, 7)

      assert length(flow_events(device)) == @revocation_records
    end
  end

  describe "a stream that jumped" do
    test "is picked up at the next section rather than decoded across the gap", %{device: device} do
      bytes = RecordingFixtures.read!(name())
      established = RecordingFixtures.read!("channel-established-logs")

      # A position that is not where the last shipment ended: the ring wrapped,
      # or the appliance restarted mid-stream. What follows opens on a section
      # header, so the stream is readable again from there.
      Telemetry.ring_bytes(device, :log, 0, bytes)
      Telemetry.ring_bytes(device, :log, byte_size(bytes) + 4_096, established)
      assert Telemetry.flush(device, :log) == :ok

      assert_received {:telemetry, :resynchronised, _measurements, %{expected: expected}}
      assert expected == byte_size(bytes)
      assert length(flow_events(device)) == @revocation_records + @established_records
    end

    test "loses only what lies before the section it resumes at", %{device: device} do
      established = RecordingFixtures.read!("channel-established-logs")
      rubbish = :binary.copy(<<0xEE>>, 512)

      Telemetry.ring_bytes(device, :log, 0, rubbish <> established)
      assert Telemetry.flush(device, :log) == :ok

      assert_received {:telemetry, :bytes_lost, %{bytes: 512}, %{ring: :log}}
      assert length(flow_events(device)) == @established_records
    end
  end

  describe "a code the schema does not declare" do
    test "costs its own row and none of the rows beside it", %{device: device} do
      bytes = RecordingFixtures.read!(name())
      ship(device, :log, undeclared_event(bytes))

      assert length(flow_events(device)) == @revocation_records - 1

      assert_received {:telemetry, :records_skipped, %{records: 1},
                       %{cause: :undeclared_code, ring: :log}}

      assert_received {:telemetry, :rows_inserted, %{rows: rows}, _metadata}
      assert rows == @revocation_records - 1
    end
  end

  describe "the capture ring" do
    test "is decoded and counted, and writes no flow event", %{device: device} do
      ship(device, :capture, RecordingFixtures.read!("channel-established-capture"))

      assert flow_events(device) == []

      assert_received {:telemetry, :records_skipped, %{records: records},
                       %{cause: :ring_not_stored, ring: :capture}}

      assert records > 0
    end

    test "does not stop the log ring of the same appliance", %{device: device} do
      ship(device, :capture, RecordingFixtures.read!("channel-established-capture"))
      ship(device, :log, RecordingFixtures.read!(name()))

      assert length(flow_events(device)) == @revocation_records
    end
  end

  describe "the metric readings a connection history carries" do
    test "become metric_samples rows a query reads back", %{device: device} do
      ship(device, :log, RecordingFixtures.read!("metric-readings-logs"))

      rows = metric_samples(device)
      assert rows != []

      # One row per catalogue slot per reading, which is what makes the count a
      # statement about the mapping rather than about how many blocks arrived.
      assert rem(length(rows), MetricCatalogue.slots()) == 0
      readings = div(length(rows), MetricCatalogue.slots())
      assert readings >= 2, "the fixture carries #{readings} reading(s)"

      # The recorder's own account of the medium under it, which a boot on the
      # harness's 64 MiB data disk reports as 131072 sectors — a number this
      # server never composed and can only have read out of the recording.
      capacity =
        Enum.filter(rows, fn row ->
          row["family"] == "librefirewall_block_capacity_sectors" and
            row["labels"]["domain"] == "recorder"
        end)

      assert length(capacity) == readings
      assert Enum.any?(capacity, &(&1["value"] == 131_072.0))

      # Every row names a series the catalogue declares, and carries the domain
      # label the shard supplies.
      declared = MapSet.new(MetricCatalogue.series())

      for row <- rows do
        labels = Map.new(row["labels"])
        assert MapSet.member?(declared, {row["family"], labels})
      end
    end

    test "carry the appliance's own instant, not this server's", %{device: device} do
      ship(device, :log, RecordingFixtures.read!("metric-readings-logs"))

      instants =
        device |> metric_samples() |> Enum.map(& &1["observed_at"]) |> Enum.uniq() |> Enum.sort()

      assert length(instants) >= 2, "every reading was stamped with one instant"
      # The readings are a second apart on the appliance, and this server took
      # them all in one call — so distinct instants can only be the appliance's.
      assert List.first(instants) != List.last(instants)
    end

    test "leave the padding that shares their block type alone", %{device: device} do
      ship(device, :log, RecordingFixtures.read!("metric-readings-logs"))

      # The fixture carries padding blocks between the readings, and a padding
      # block read as a reading would put four hundred fabricated numbers in the
      # store. Nothing is counted as a skipped record for them: padding is not a
      # fault and is stepped over in silence.
      refute_received {:telemetry, :records_skipped, _measurements, %{cause: :padding}}
      refute_received {:telemetry, :samples_skipped, _measurements, _metadata}
    end

    test "and the connection history's own records land beside them", %{device: device} do
      ship(device, :log, RecordingFixtures.read!("metric-readings-logs"))

      # Two tables from one ring, and the cursor moved once both were in.
      assert metric_samples(device) != []
      assert Cursor.position(device, :log) > 0
    end
  end

  describe "a ring's process" do
    test "lives as long as the session feeding it, and leaves nothing behind", %{device: device} do
      test = self()

      session =
        spawn(fn ->
          Telemetry.ring_bytes(device, :log, 0, RecordingFixtures.read!(name()))
          send(test, :shipped)
          receive(do: (:disconnect -> :ok))
        end)

      assert_receive :shipped
      ring = GenServer.whereis(Telemetry.name(device, :log))
      assert is_pid(ring)

      monitor = Process.monitor(ring)
      send(session, :disconnect)

      assert_receive {:DOWN, ^monitor, :process, ^ring, :normal}
      refute GenServer.whereis(Telemetry.name(device, :log))

      # What it was holding went in on the way out: an appliance that
      # disconnected has already decoded those records, and the store is
      # reachable whether or not the wire still is.
      assert length(flow_events(device)) == @revocation_records
    end
  end

  describe "the ingest's own bounds" do
    test "are first-party constants rather than anything a peer states" do
      assert Ring.batch_rows() > 0
      assert Ring.batch_age() > 0
      assert Telemetry.storing_ring() == :log
    end

    test "name every event this ingest emits" do
      for event <- Telemetry.events() do
        assert Enum.take(event, 4) == Telemetry.prefix()
      end
    end
  end

  describe "a store that will not take the rows" do
    test "says so with what the store said, and keeps the cursor where it was", %{device: device} do
      configured = Application.get_env(:ctrld, Store)
      on_exit(fn -> Application.put_env(:ctrld, Store, configured) end)
      Application.put_env(:ctrld, Store, Keyword.put(configured, :url, nil))

      Telemetry.ring_bytes(device, :log, 0, RecordingFixtures.read!(name()))
      assert Telemetry.flush(device, :log) == {:error, :not_configured}

      assert_received {:telemetry, :insert_failed, %{rows: @revocation_records},
                       %{reason: :not_configured}}

      assert Cursor.position(device, :log) == 0

      # The rows were held rather than thrown away, so a store that comes back
      # takes them: the commonest reason an insert fails is one that restarted.
      Application.put_env(:ctrld, Store, configured)
      assert Telemetry.flush(device, :log) == :ok
      assert length(flow_events(device)) == @revocation_records
    end
  end

  defp name, do: "policy-revocation-logs"

  defp ship(device, ring, bytes) do
    assert Telemetry.ring_bytes(device, ring, 0, bytes) == :ok
    assert Telemetry.flush(device, ring) == :ok
  end

  defp split(device, ring, bytes, size) do
    bytes
    |> chunks(size)
    |> Enum.reduce(0, fn piece, position ->
      assert Telemetry.ring_bytes(device, ring, position, piece) == :ok
      position + byte_size(piece)
    end)

    assert Telemetry.flush(device, ring) == :ok
  end

  defp chunks(bytes, size) when byte_size(bytes) <= size, do: [bytes]

  defp chunks(bytes, size) do
    [
      binary_part(bytes, 0, size)
      | chunks(binary_part(bytes, size, byte_size(bytes) - size), size)
    ]
  end

  defp metric_samples(device) do
    {:ok, rows} =
      Store.query(
        "SELECT * FROM metric_samples WHERE device_id = '#{device}' " <>
          "ORDER BY observed_at, family"
      )

    rows
  end

  defp flow_events(device) do
    {:ok, rows} =
      Store.query(
        "SELECT * FROM flow_events WHERE device_id = '#{device}' " <>
          "ORDER BY observed_at, flow_slot, flow_occupant"
      )

    rows
  end

  # Everything a row says about the traffic, without the two columns that are
  # about this server's own handling of it: the appliance the row came from and
  # the instant it was written here.
  defp comparable(rows), do: Enum.map(rows, &Map.drop(&1, ["device_id", "ingested_at"]))

  # One record's annotation, with its event moved to a code the schema does not
  # declare — aimed at the field by walking the block's options rather than by a
  # number written here, so a fixture that grew an option still hits it.
  defp undeclared_event(bytes) do
    {offset, _total} = RecordingFixtures.block!(bytes, 0x0000_0006)
    at = annotation_at(bytes, RecordingFixtures.packet_options_at(bytes, offset))
    RecordingFixtures.patch(bytes, at + 6, <<200>>)
  end

  defp annotation_at(bytes, at) do
    <<code::unsigned-little-16, length::unsigned-little-16>> = binary_part(bytes, at, 4)

    if code == 2989 do
      # The value opens on the Private Enterprise Number; the layout is behind it.
      at + 4 + 4
    else
      annotation_at(bytes, at + 4 + length + rem(4 - rem(length, 4), 4))
    end
  end
end
