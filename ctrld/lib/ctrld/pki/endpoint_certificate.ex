defmodule Ctrld.PKI.EndpointCertificate do
  @moduledoc """
  The channel endpoint's server certificate as it is stored.

  This is the certificate an appliance will see when it dials, and it is the
  reason the authority above exists at all: the appliance validates it against
  the trust anchor the package delivered and against nothing else — no system
  roots, no other authority.

  Its key is sealed under its own context, so it and an authority key are not
  interchangeable even to somebody holding the key-encryption key.
  """

  use Ecto.Schema

  import Ecto.Changeset

  schema "endpoint_certificates" do
    field(:endpoint, :string)
    field(:key_algorithm, :string)
    field(:signature_algorithm, :string)
    field(:certificate_der, :binary)
    field(:serial, :string)
    field(:spki_fingerprint, :string)
    field(:not_before, :utc_datetime)
    field(:not_after, :utc_datetime)
    field(:sealed_key, :binary)
    field(:sealed_key_iv, :binary)
    field(:sealed_key_tag, :binary)
    field(:retired_at, :utc_datetime)
    belongs_to(:certificate_authority, Ctrld.PKI.CertificateAuthority)

    timestamps(type: :utc_datetime)
  end

  @doc "The associated data every private key in this table is sealed under."
  @spec sealing_context() :: binary()
  def sealing_context, do: "ctrld:endpoint_certificate:private_key"

  @doc false
  def changeset(certificate, attributes) do
    certificate
    |> cast(attributes, [
      :certificate_authority_id,
      :endpoint,
      :key_algorithm,
      :signature_algorithm,
      :certificate_der,
      :serial,
      :spki_fingerprint,
      :not_before,
      :not_after,
      :sealed_key,
      :sealed_key_iv,
      :sealed_key_tag,
      :retired_at
    ])
    |> validate_required([
      :certificate_authority_id,
      :endpoint,
      :key_algorithm,
      :signature_algorithm,
      :certificate_der,
      :serial,
      :spki_fingerprint,
      :not_before,
      :not_after,
      :sealed_key,
      :sealed_key_iv,
      :sealed_key_tag
    ])
    |> assoc_constraint(:certificate_authority)
    |> unique_constraint(:retired_at, name: :endpoint_certificates_one_active_index)
  end
end
