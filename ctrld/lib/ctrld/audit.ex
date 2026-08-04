defmodule Ctrld.Audit do
  @moduledoc """
  The audit trail: every state-changing action an administrator takes.

  Recording is not optional and is not best-effort. `record/1` returns a
  changeset operation the caller runs inside the same transaction as the
  change it describes, so a change that lands without its record cannot
  happen — the two commit together or neither does.
  """

  import Ecto.Query

  alias Ctrld.Audit.Event
  alias Ctrld.Repo

  @doc "The insert operation for one event, to run in the caller's transaction."
  @spec record(map()) :: Ecto.Changeset.t()
  def record(attributes), do: Event.changeset(%Event{}, attributes)

  @doc "Write one event on its own, where there is no wider transaction to join."
  @spec write!(map()) :: Event.t()
  def write!(attributes), do: attributes |> record() |> Repo.insert!()

  @doc "The trail, newest first, bounded."
  @spec list_events(pos_integer()) :: [Event.t()]
  def list_events(limit \\ 200) when is_integer(limit) and limit > 0 do
    Repo.all(
      from(event in Event,
        order_by: [desc: event.id],
        limit: ^limit,
        preload: [:actor]
      )
    )
  end

  @doc "The trail for one subject, newest first."
  @spec list_events_for(String.t(), String.t()) :: [Event.t()]
  def list_events_for(subject_type, subject_id) do
    Repo.all(
      from(event in Event,
        where: event.subject_type == ^subject_type and event.subject_id == ^subject_id,
        order_by: [desc: event.id],
        preload: [:actor]
      )
    )
  end
end
