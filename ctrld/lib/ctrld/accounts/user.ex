defmodule Ctrld.Accounts.User do
  @moduledoc """
  A local account.

  Authentication in this release is local accounts only; identity-provider
  federation comes later, and SAML is never implemented here. The role column
  exists with one value because the audit record names an actor and an actor
  has to be something — it is a field of the record, not an access-control
  mechanism, and there is no second role to be granted.
  """

  use Ecto.Schema

  import Ecto.Changeset

  alias Ctrld.Accounts.Password

  @roles ~w(administrator)

  schema "users" do
    field(:email, :string)
    field(:hashed_password, :string)
    field(:role, :string)
    field(:password, :string, virtual: true, redact: true)

    timestamps(type: :utc_datetime)
  end

  @doc "The roles an account may hold."
  def roles, do: @roles

  @doc "Create an account from an address and a password."
  def changeset(user, attributes) do
    user
    |> cast(attributes, [:email, :password, :role])
    |> validate_required([:email, :password, :role])
    |> validate_inclusion(:role, @roles)
    |> update_change(:email, &(&1 |> String.trim() |> String.downcase()))
    |> validate_format(:email, ~r/^[^\s@]+@[^\s@]+$/, message: "is not an address")
    |> validate_length(:email, max: 160)
    |> validate_length(:password, min: 12, max: 72)
    |> put_hashed_password()
    |> unique_constraint(:email)
  end

  defp put_hashed_password(changeset) do
    case get_change(changeset, :password) do
      nil ->
        changeset

      password ->
        changeset
        |> put_change(:hashed_password, Password.hash(password))
        |> delete_change(:password)
    end
  end
end
