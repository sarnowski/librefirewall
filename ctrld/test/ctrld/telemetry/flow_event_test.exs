defmodule Ctrld.Telemetry.FlowEventTest do
  @moduledoc """
  A decoded record turned into the row `flow_events` holds.

  Every record here comes out of a committed fixture the appliance's own
  encoder wrote, so what is under test is the join of three real things — an
  instant, an annotation and a frame — and not a row assembled to pass.
  """

  use ExUnit.Case, async: true

  alias Ctrld.{Pcapng, RecordingFixtures}
  alias Ctrld.Pcapng.{Annotation, Packet}
  alias Ctrld.Telemetry.{FiveTuple, FlowEvent, Schema}

  @device "0123456789abcdef0123456789abcdef"

  defp records(name) do
    {:ok, blocks, _decoder} = Pcapng.decode(Pcapng.new(), RecordingFixtures.read!(name))
    Enum.filter(blocks, &match?(%Packet{}, &1))
  end

  defp row!(record) do
    {:row, row, refusal} = FlowEvent.row(@device, record)
    {row, refusal}
  end

  describe "a record the appliance wrote" do
    test "becomes the row its annotation and its frame say" do
      {row, refusal} = "policy-revocation-logs" |> records() |> hd() |> row!()

      assert refusal == nil
      assert row.device_id == @device
      assert row.observed_at == "2026-08-10 22:51:46.044152"
      assert row.verdict == 0
      assert row.event == 1
      assert row.flow_class == 1
      assert row.drop_reason == 0
      assert row.flow_state == 9
      assert row.generation == 1
      assert row.flow_slot == 0
      assert row.flow_occupant == 1
      assert row.matched_rule == 2
      assert row.interface_id == 0
      assert row.direction == 0
      assert row.protocol == 17
      assert row.source_address == "10.0.0.2"
      assert row.destination_address == "10.0.1.2"
      assert row.source_port == 4444
      assert row.destination_port == 5000
    end

    test "carries the annotation's flow generation as the slot's occupant" do
      record = "policy-revocation-logs" |> records() |> Enum.at(1)
      {row, nil} = row!(record)

      assert %Annotation{flow_generation: occupant, classification: class} = record.annotation
      assert row.flow_occupant == occupant
      assert row.flow_class == class
    end

    test "reads a drop with the reason the appliance gave it" do
      {row, nil} = "policy-revocation-logs" |> records() |> Enum.at(5) |> row!()

      assert row.verdict == 1
      assert row.drop_reason == 26
      assert row.event == 5
      assert row.source_port == 5000
      assert row.destination_port == 4445
    end

    test "every record in every fixture yields a row" do
      for name <- RecordingFixtures.names(), record <- records(name) do
        assert {:row, _row, _refusal} = FlowEvent.row(@device, record),
               "#{name} holds a record this build builds no row for"
      end
    end
  end

  describe "a record about no frame" do
    test "keeps its verdict and says nothing about a conversation" do
      record = "policy-revocation-logs" |> records() |> Enum.find(&(&1.data == <<>>))
      {row, refusal} = row!(record)

      assert refusal == :no_frame
      assert row.verdict == 2
      assert row.event == 7
      assert row.generation == 2
      assert row.flow_slot == 1

      assert row.protocol == FiveTuple.unread_protocol()
      assert row.source_address == "0.0.0.0"
      assert row.destination_address == "0.0.0.0"
      assert row.source_port == 0
      assert row.destination_port == 0
    end

    test "is the only shape a row whose frame was read cannot take" do
      # The protocol is what tells the two apart, and it is not a convention
      # this test states — it is what every readable frame in every fixture
      # carries, checked rather than asserted in prose.
      for name <- RecordingFixtures.names(), record <- records(name), record.data != <<>> do
        {row, nil} = row!(record)
        refute row.protocol == FiveTuple.unread_protocol()
      end
    end
  end

  describe "a record with no row" do
    test "is one whose annotation this build could not read" do
      record = "policy-revocation-logs" |> records() |> hd()

      assert FlowEvent.row(@device, %{record | annotation: nil}) ==
               {:no_row, :annotation_unrecognised}
    end

    test "is one whose vocabulary has grown past the schema" do
      record = "policy-revocation-logs" |> records() |> hd()
      beyond = %{record.annotation | event: 200}

      assert FlowEvent.row(@device, %{record | annotation: beyond}) ==
               {:no_row, {:undeclared_code, :event, 200}}
    end

    test "is refused for each of the four columns the schema enumerates" do
      record = "policy-revocation-logs" |> records() |> hd()

      for {column, field} <- [
            {:direction, :direction},
            {:verdict, :verdict},
            {:flow_class, :classification},
            {:event, :event}
          ] do
        beyond = Map.put(record.annotation, field, 250)

        assert FlowEvent.row(@device, %{record | annotation: beyond}) ==
                 {:no_row, {:undeclared_code, column, 250}}
      end
    end

    test "is never one whose code the schema does declare" do
      record = "policy-revocation-logs" |> records() |> hd()

      for {column, members} <- Schema.flow_event_enums(), code <- Map.keys(members) do
        field = if column == :flow_class, do: :classification, else: column
        within = Map.put(record.annotation, field, code)

        assert {:row, _row, _refusal} = FlowEvent.row(@device, %{record | annotation: within})
      end
    end
  end

  describe "refusals" do
    test "every one renders as a sentence" do
      for refusal <- [:annotation_unrecognised, {:undeclared_code, :verdict, 9}] do
        assert is_binary(FlowEvent.describe(refusal))
      end
    end
  end
end
