defmodule Ctrld.Appliances.ConfigurationVersion do
  @moduledoc """
  One version of one appliance's configuration document.

  Generations are the appliance's own numbering and start at one, which is the
  document the onboarding package carried. There are no staging, commit or
  confirmation timestamps here: those are facts a channel's configuration
  operations establish, this server carries out none of them yet, and a column
  nothing ever writes reads as a fact nobody has.
  """

  use Ecto.Schema

  import Ecto.Changeset

  schema "configuration_versions" do
    field(:generation, :integer)
    field(:document, :string)
    field(:document_sha256, :string)

    belongs_to(:appliance, Ctrld.Appliances.Appliance)
    belongs_to(:author, Ctrld.Accounts.User)

    timestamps(type: :utc_datetime)
  end

  @doc "The digest a document is recorded under, as 64 lowercase hexadecimal characters."
  @spec digest(binary()) :: String.t()
  def digest(document) when is_binary(document) do
    :sha256 |> :crypto.hash(document) |> Base.encode16(case: :lower)
  end

  @doc false
  def changeset(version, attributes) do
    version
    |> cast(attributes, [:appliance_id, :generation, :document, :document_sha256, :author_id])
    |> validate_required([:generation, :document, :document_sha256])
    |> validate_number(:generation, greater_than: 0)
    |> unique_constraint([:appliance_id, :generation])
  end
end
