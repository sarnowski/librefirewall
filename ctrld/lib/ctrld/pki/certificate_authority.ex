defmodule Ctrld.PKI.CertificateAuthority do
  @moduledoc """
  The management certificate authority as it is stored.

  Its private key is on the row sealed, never in the clear, and the sealing
  context below is what binds a ciphertext to this table: a sealed key lifted
  out of here and written anywhere else opens to nothing.
  """

  use Ecto.Schema

  import Ecto.Changeset

  schema "certificate_authorities" do
    field(:name, :string)
    field(:key_algorithm, :string)
    field(:signature_algorithm, :string)
    field(:certificate_der, :binary)
    field(:serial, :string)
    field(:subject_common_name, :string)
    field(:spki_fingerprint, :string)
    field(:not_before, :utc_datetime)
    field(:not_after, :utc_datetime)
    field(:sealed_key, :binary)
    field(:sealed_key_iv, :binary)
    field(:sealed_key_tag, :binary)
    field(:retired_at, :utc_datetime)

    timestamps(type: :utc_datetime)
  end

  @doc "The associated data every private key in this table is sealed under."
  @spec sealing_context() :: binary()
  def sealing_context, do: "ctrld:certificate_authority:private_key"

  @doc false
  def changeset(authority, attributes) do
    authority
    |> cast(attributes, [
      :name,
      :key_algorithm,
      :signature_algorithm,
      :certificate_der,
      :serial,
      :subject_common_name,
      :spki_fingerprint,
      :not_before,
      :not_after,
      :sealed_key,
      :sealed_key_iv,
      :sealed_key_tag,
      :retired_at
    ])
    |> validate_required([
      :name,
      :key_algorithm,
      :signature_algorithm,
      :certificate_der,
      :serial,
      :subject_common_name,
      :spki_fingerprint,
      :not_before,
      :not_after,
      :sealed_key,
      :sealed_key_iv,
      :sealed_key_tag
    ])
    |> unique_constraint(:spki_fingerprint)
    |> unique_constraint(:retired_at, name: :certificate_authorities_one_active_index)
  end
end
