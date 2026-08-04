defmodule Ctrld.Repo.Migrations.CreateAuditEvents do
  use Ecto.Migration

  def change do
    create table(:audit_events) do
      add :actor_id, references(:users, on_delete: :nilify_all)
      # The actor's address as it was at the time. An audit record that
      # becomes anonymous when an account is deleted is an audit record that
      # stops answering the question it exists for.
      add :actor_email, :string, null: false
      add :action, :string, null: false
      add :subject_type, :string, null: false
      add :subject_id, :string, null: false
      add :detail, :map, null: false, default: %{}

      timestamps(type: :utc_datetime, updated_at: false)
    end

    create index(:audit_events, [:inserted_at])
    create index(:audit_events, [:subject_type, :subject_id])
  end
end
