defmodule Ctrld.Repo.Migrations.CreateAccounts do
  use Ecto.Migration

  def change do
    create table(:users) do
      add :email, :string, null: false
      add :hashed_password, :string, null: false
      add :role, :string, null: false

      timestamps(type: :utc_datetime)
    end

    # Addresses are stored already normalised, so the unique index is over the
    # stored value and there is no second notion of "the same account".
    create unique_index(:users, [:email])

    create table(:user_tokens) do
      add :user_id, references(:users, on_delete: :delete_all), null: false
      # The digest of the session token, never the token: a database read must
      # not hand out a live session.
      add :hashed_token, :binary, null: false
      add :context, :string, null: false

      timestamps(type: :utc_datetime, updated_at: false)
    end

    create index(:user_tokens, [:user_id])
    create unique_index(:user_tokens, [:context, :hashed_token])
  end
end
