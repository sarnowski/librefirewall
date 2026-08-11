defmodule Ctrld.Appliances.Appliance do
  @moduledoc """
  One onboarded appliance.

  There is no status column, deliberately. A status the server stores is a
  status that can disagree with what the server can actually evidence, and the
  inventory is supposed to be honest above all else — so status is derived from
  the facts on the row and nothing else, by `Ctrld.Appliances.status/1`.

  Three of those facts are here. A request arrived and a certificate was issued,
  which is what makes an appliance onboarded. `connected_since` is a channel
  session that is open *now*: the listener sets it when a session opens, clears
  it when the session closes, and clears every row's as it starts, because a
  session cannot outlive the process that held it — which is what keeps the
  column from becoming a remembered value that reads as a live one.
  `last_seen_at` is the remembered half, and it is what tells an appliance that
  has been away from one that has never dialled at all.
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
    field(:connected_since, :utc_datetime)
    field(:last_seen_at, :utc_datetime)

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

  @doc """
  The two connection facts, and nothing else.

  A separate changeset because a channel session must not be able to write an
  identity: the transport reaches this row on every connection an appliance
  makes, and the certificate, the key fingerprint and the endpoint are not
  things a connection may change. The two names below are the whole of what it
  will carry, so an attribute outside them is dropped rather than honoured.

  Each named field is **forced**, and that is the load-bearing part. A session
  transition is a statement about the world and not a difference from the
  caller's copy of the row: an ordinary cast is dropped where the value it
  carries already matches that copy, which would make clearing a live session
  depend on the caller holding a struct that still remembered one — and the
  caller closing a session is precisely the one that may not. An inventory that
  says online because a stale struct made a clear into a no-op is the one failure
  a derived status was supposed to make impossible.
  """
  def session_changeset(appliance, attributes) when is_map(attributes) do
    Enum.reduce([:connected_since, :last_seen_at], change(appliance), fn field, changeset ->
      case Map.fetch(attributes, field) do
        {:ok, value} -> force_change(changeset, field, value)
        :error -> changeset
      end
    end)
  end
end
