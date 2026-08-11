defmodule Ctrld.Telemetry.Cursor do
  @moduledoc """
  How far into a recording ring this server has durably stored what it read.

  One row per appliance and ring, holding the ring's own absolute append
  position that everything below has been decoded from and written to the
  telemetry store. It is the answer to at-least-once delivery: an appliance
  re-ships a ring from its beginning on every reconnect and every reboot, and
  bytes at or below this mark are bytes whose rows are already in ClickHouse,
  so they are skipped rather than inserted a second time.

  The mark moves only *after* an insert has been acknowledged, and only as far
  as the last block that insert covered — never as far as the bytes that
  arrived, which may end in the middle of a block. So a crash or a failed
  insert costs a re-decode of what was in flight and never a gap: the position
  is the last place from which resuming is known to lose nothing.

  It never moves backwards. A reconnect can leave two readers of one ring
  overlapping for as long as it takes the older to notice, and a mark that took
  whichever of them wrote last would hand the newer one work it had already
  done — so the write keeps the larger of the two.
  """

  use Ecto.Schema

  import Ecto.Query

  alias Ctrld.Channel.Frame
  alias Ctrld.Repo

  # The two rings, as the column spells them. A ring read back out of the
  # database is matched against this list rather than turned into an atom,
  # because a row is data and the vocabulary is closed.
  @rings %{log: "log", capture: "capture"}

  schema "telemetry_ingest_cursors" do
    field(:device_id, :string)
    field(:ring, :string)
    field(:position, :integer)

    timestamps(type: :utc_datetime)
  end

  @doc """
  The position everything below which is already stored.

  Zero for a ring this server has never stored anything from, which is the
  honest answer: nothing has been ingested, so nothing may be skipped.
  """
  @spec position(String.t(), Frame.ring()) :: non_neg_integer()
  def position(device_id, ring) when is_binary(device_id) and is_map_key(@rings, ring) do
    name = Map.fetch!(@rings, ring)

    query =
      from(cursor in __MODULE__,
        where: cursor.device_id == ^device_id and cursor.ring == ^name,
        select: cursor.position
      )

    Repo.one(query) || 0
  end

  @doc """
  Record that everything below `position` is stored.

  Idempotent and monotonic: writing a position at or below the one held leaves
  the row as it was.
  """
  @spec advance(String.t(), Frame.ring(), non_neg_integer()) :: :ok
  def advance(device_id, ring, position)
      when is_binary(device_id) and is_map_key(@rings, ring) and is_integer(position) and
             position >= 0 do
    now = DateTime.utc_now() |> DateTime.truncate(:second)

    record = %__MODULE__{
      device_id: device_id,
      ring: Map.fetch!(@rings, ring),
      position: position,
      inserted_at: now,
      updated_at: now
    }

    {:ok, _cursor} =
      Repo.insert(record,
        on_conflict:
          from(cursor in __MODULE__,
            update: [
              set: [
                position: fragment("GREATEST(?, EXCLUDED.position)", cursor.position),
                updated_at: ^now
              ]
            ]
          ),
        conflict_target: [:device_id, :ring]
      )

    :ok
  end
end
