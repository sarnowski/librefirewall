defmodule Ctrld.Telemetry.StoreTest do
  @moduledoc """
  The telemetry store against a real ClickHouse.

  Every test here needs the store to answer, and the suite refuses to start
  without one, so a green run means these rows really went in and came back.
  Rows are keyed by a device identifier minted per test, so no test can see
  another's rows in the one shared schema.
  """

  # Not async: one test unsets the store's configuration, which is process-
  # independent state every other test here reads.
  use ExUnit.Case, async: false

  alias Ctrld.Telemetry.{Schema, Store}

  defp device_id do
    :crypto.strong_rand_bytes(16) |> Base.encode16(case: :lower)
  end

  describe "the schema" do
    test "is applied, and applying it again changes nothing" do
      assert Store.migrate() == :ok
      assert Store.migrate() == :ok
    end

    test "holds every table the appliance produces for" do
      assert {:ok, rows} =
               Store.query("SELECT name FROM system.tables WHERE database = currentDatabase()")

      names = Enum.map(rows, & &1["name"])
      for table <- Schema.tables(), do: assert(table in names)
    end
  end

  describe "flow events" do
    test "a row round-trips with every field intact" do
      device = device_id()

      row = %{
        device_id: device,
        observed_at: "2026-08-04 12:00:00.123456",
        generation: 7,
        interface_id: 1,
        direction: "inbound",
        verdict: "dropped",
        drop_reason: 4,
        flow_class: "new",
        event: "policy-denied",
        flow_state: 2,
        flow_slot: 4096,
        flow_occupant: 3,
        matched_rule: 12,
        protocol: 17,
        source_address: "10.0.0.2",
        destination_address: "10.0.1.2",
        source_port: 40_000,
        destination_port: 5001
      }

      assert :ok = Store.insert("flow_events", [row])

      assert {:ok, [read]} =
               Store.query(
                 "SELECT * FROM flow_events WHERE device_id = '#{device}' ORDER BY observed_at"
               )

      assert read["device_id"] == device
      assert read["generation"] == 7
      assert read["direction"] == "inbound"
      assert read["verdict"] == "dropped"
      assert read["event"] == "policy-denied"
      assert read["flow_class"] == "new"
      assert read["matched_rule"] == 12
      assert read["source_address"] == "10.0.0.2"
      assert read["destination_port"] == 5001
      assert read["ingested_at"] != nil
    end

    test "a batch goes in as one statement" do
      device = device_id()

      rows =
        for slot <- 1..25 do
          %{
            device_id: device,
            observed_at: "2026-08-04 12:00:00.000000",
            generation: 1,
            interface_id: 0,
            direction: "outbound",
            verdict: "forwarded",
            drop_reason: 0,
            flow_class: "established",
            event: "flow-advanced",
            flow_state: 3,
            flow_slot: slot,
            flow_occupant: 1,
            matched_rule: 0,
            protocol: 6,
            source_address: "10.0.0.2",
            destination_address: "10.0.1.2",
            source_port: 1234,
            destination_port: 443
          }
        end

      assert :ok = Store.insert("flow_events", rows)

      assert {:ok, [%{"count" => count}]} =
               Store.query(
                 "SELECT count() AS count FROM flow_events WHERE device_id = '#{device}'"
               )

      assert to_integer(count) == 25
    end

    test "an enumeration value the schema does not name is refused by the store" do
      device = device_id()

      row = %{
        device_id: device,
        observed_at: "2026-08-04 12:00:00.000000",
        generation: 1,
        interface_id: 0,
        direction: "sideways",
        verdict: "forwarded",
        drop_reason: 0,
        flow_class: "new",
        event: "none",
        flow_state: 0,
        flow_slot: 0,
        flow_occupant: 0,
        matched_rule: 0,
        protocol: 6,
        source_address: "10.0.0.2",
        destination_address: "10.0.1.2",
        source_port: 1,
        destination_port: 1
      }

      assert {:error, {:http, _status, _body}} = Store.insert("flow_events", [row])
    end
  end

  describe "log events" do
    test "a row round-trips" do
      device = device_id()

      assert :ok =
               Store.insert("log_events", [
                 %{
                   device_id: device,
                   observed_at: "2026-08-04 12:00:00.000000",
                   domain: "forwarder",
                   severity: "info",
                   event: "configuration-committed",
                   detail: "generation=2"
                 }
               ])

      assert {:ok, [read]} =
               Store.query("SELECT * FROM log_events WHERE device_id = '#{device}'")

      assert read["domain"] == "forwarder"
      assert read["detail"] == "generation=2"
    end
  end

  describe "metric samples" do
    test "a row round-trips with its labels" do
      device = device_id()

      assert :ok =
               Store.insert("metric_samples", [
                 %{
                   device_id: device,
                   observed_at: "2026-08-04 12:00:00.000000",
                   family: "librefirewall_frames_total",
                   labels: %{"interface" => "dataplane-0", "verdict" => "forwarded"},
                   value: 1234.0
                 }
               ])

      assert {:ok, [read]} =
               Store.query("SELECT * FROM metric_samples WHERE device_id = '#{device}'")

      assert read["family"] == "librefirewall_frames_total"
      assert read["labels"] == %{"interface" => "dataplane-0", "verdict" => "forwarded"}
      assert read["value"] == 1234.0
    end
  end

  describe "refusals" do
    test "a table the schema does not own is refused before a statement is built" do
      assert Store.insert("system.tables", [%{a: 1}]) ==
               {:error, {:unknown_table, "system.tables"}}
    end

    test "an empty batch is a no-operation rather than a malformed statement" do
      assert Store.insert("flow_events", []) == :ok
    end

    test "a statement the store rejects comes back with what the store said" do
      assert {:error, {:http, status, body}} = Store.execute("SELECT nonsense_function()")
      assert status >= 400
      assert body != ""
    end

    test "an unconfigured store says so rather than reaching for a default" do
      configured = Application.get_env(:ctrld, Store)
      on_exit(fn -> Application.put_env(:ctrld, Store, configured) end)

      Application.put_env(:ctrld, Store, url: nil)
      assert Store.execute("SELECT 1") == {:error, :not_configured}
      refute Store.ready?()
    end

    test "every refusal renders as a sentence" do
      for reason <- [
            :not_configured,
            {:http, 400, "bad"},
            {:transport, :econnrefused},
            {:unknown_table, "x"}
          ] do
        assert is_binary(Store.describe(reason))
      end
    end
  end

  defp to_integer(value) when is_integer(value), do: value
  defp to_integer(value) when is_binary(value), do: String.to_integer(value)
end
