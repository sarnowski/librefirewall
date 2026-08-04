defmodule Ctrld.Appliances.Appliance do
  @moduledoc """
  One onboarded appliance.

  There is no status column, deliberately. A status the server stores is a
  status that can disagree with what the server can actually evidence, and the
  inventory is supposed to be honest above all else — so status is derived
  from the facts on the row and nothing else. Today those facts are that a
  request arrived and a certificate was issued, and that derivation is
  `Ctrld.Appliances.status/1`. Online, offline and last seen become facts when
  a connection establishes them, and the columns for them arrive with the
  connection.
  """

  use Ecto.Schema

  import Ecto.Changeset

  schema "appliances" do
    field(:device_id, :string)
    field(:name, :string)
    field(:spki_fingerprint, :string)
    field(:csr_pem, :string)
    field(:csr_received_at, :utc_datetime)
    field(:certificate_der, :binary)
    field(:certificate_serial, :string)
    field(:certificate_issued_at, :utc_datetime)
    field(:certificate_not_after, :utc_datetime)
    field(:endpoint, :string)

    belongs_to(:certificate_authority, Ctrld.PKI.CertificateAuthority)
    belongs_to(:onboarded_by, Ctrld.Accounts.User)
    has_many(:configuration_versions, Ctrld.Appliances.ConfigurationVersion)

    timestamps(type: :utc_datetime)
  end

  @doc false
  def changeset(appliance, attributes) do
    appliance
    |> cast(attributes, [
      :device_id,
      :name,
      :spki_fingerprint,
      :csr_pem,
      :csr_received_at,
      :certificate_authority_id,
      :certificate_der,
      :certificate_serial,
      :certificate_issued_at,
      :certificate_not_after,
      :endpoint,
      :onboarded_by_id
    ])
    |> validate_required([
      :device_id,
      :name,
      :spki_fingerprint,
      :csr_pem,
      :csr_received_at,
      :certificate_authority_id,
      :certificate_der,
      :certificate_serial,
      :certificate_issued_at,
      :certificate_not_after,
      :endpoint
    ])
    |> validate_length(:name, min: 1, max: 120)
    |> update_change(:name, &String.trim/1)
    |> unique_constraint(:device_id)
    |> unique_constraint(:spki_fingerprint)
    |> assoc_constraint(:certificate_authority)
  end
end
