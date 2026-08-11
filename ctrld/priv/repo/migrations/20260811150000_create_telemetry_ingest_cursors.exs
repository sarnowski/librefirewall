defmodule Ctrld.Repo.Migrations.CreateTelemetryIngestCursors do
  use Ecto.Migration

  # How far into each recording ring this server has durably stored what it
  # read, per appliance and ring.
  #
  # It exists because delivery is at-least-once and an appliance re-ships a ring
  # from its beginning on every reconnect and every reboot. Without a durable
  # mark, the second delivery of a stream is a second copy of every row in it,
  # and a telemetry store that answers "three" to a question about one flow is
  # worse than one that answers nothing. The mark is here rather than in
  # ClickHouse because it must be exact the instant it is written: a
  # deduplicating table answers correctly only once a background merge has run,
  # and "eventually not duplicated" is not what a query needs.
  #
  # The position is the ring's own absolute append coordinate — the appliance's
  # number, not an offset into anything here — so it survives a restart of this
  # server and means the same thing to both ends.
  def change do
    create table(:telemetry_ingest_cursors) do
      add(:device_id, :string, null: false)
      add(:ring, :string, null: false)
      add(:position, :bigint, null: false)

      timestamps(type: :utc_datetime)
    end

    create(unique_index(:telemetry_ingest_cursors, [:device_id, :ring]))
  end
end
