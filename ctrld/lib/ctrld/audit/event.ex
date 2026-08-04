defmodule Ctrld.Audit.Event do
  @moduledoc """
  One thing an administrator did.

  The actor is kept twice — as a reference and as the address it was at the
  time — because the reference can go away and the record must not stop
  answering who acted.
  """

  use Ecto.Schema

  import Ecto.Changeset

  schema "audit_events" do
    field(:actor_email, :string)
    field(:action, :string)
    field(:subject_type, :string)
    field(:subject_id, :string)
    field(:detail, :map, default: %{})
    belongs_to(:actor, Ctrld.Accounts.User)

    timestamps(type: :utc_datetime, updated_at: false)
  end

  @doc false
  def changeset(event, attributes) do
    event
    |> cast(attributes, [:actor_id, :actor_email, :action, :subject_type, :subject_id, :detail])
    |> validate_required([:actor_email, :action, :subject_type, :subject_id])
  end
end
