defmodule Ctrld.PKI do
  @moduledoc """
  The server as certificate authority.

  It holds the authority it signs with and the channel endpoint's server
  certificate, both with their private keys sealed in the database, and it
  issues device certificates against `Ctrld.PKI.Profile`. Signing happens
  here and nowhere else, so there is exactly one place a private key is
  unsealed and exactly one place it is used.
  """

  import Ecto.Query

  alias Ctrld.PKI.{Certificate, CertificateAuthority, EndpointCertificate, KeyPair, Profile}
  alias Ctrld.{ChannelEndpoint, Repo, Vault}

  @doc "The signing authority, or nil before there is one."
  @spec active_authority() :: CertificateAuthority.t() | nil
  def active_authority do
    Repo.one(from(authority in CertificateAuthority, where: is_nil(authority.retired_at)))
  end

  @doc "The signing authority, or a refusal — nothing can be issued without one."
  @spec active_authority!() :: CertificateAuthority.t()
  def active_authority! do
    active_authority() ||
      raise "the management server holds no active certificate authority; it cannot issue"
  end

  @doc "The channel endpoint's current server certificate, or nil."
  @spec active_endpoint_certificate() :: EndpointCertificate.t() | nil
  def active_endpoint_certificate do
    Repo.one(
      from(certificate in EndpointCertificate,
        where: is_nil(certificate.retired_at),
        preload: [:certificate_authority]
      )
    )
  end

  @doc """
  Create the signing authority.

  The key is generated, used to self-sign, sealed, and dropped; nothing but
  the sealed form is ever written. A name that will not fit the profile's
  certificate bound is refused before anything is sealed or inserted.
  """
  @spec create_authority(String.t(), DateTime.t()) ::
          {:ok, CertificateAuthority.t()} | {:error, Ecto.Changeset.t() | Certificate.reason()}
  def create_authority(name, now \\ DateTime.utc_now()) do
    with {:ok, {issued, key}} <- Certificate.create_authority(name, now) do
      insert_authority(issued, key, name)
    end
  end

  defp insert_authority(issued, key, name) do
    sealed = Vault.seal(KeyPair.private_key_pem(key), CertificateAuthority.sealing_context())

    %CertificateAuthority{}
    |> CertificateAuthority.changeset(%{
      name: name,
      key_algorithm: Profile.key_algorithm(),
      signature_algorithm: Profile.signature_algorithm(),
      certificate_der: issued.der,
      serial: Integer.to_string(issued.serial),
      subject_common_name: issued.subject_common_name,
      spki_fingerprint: issued.spki_fingerprint,
      not_before: issued.not_before,
      not_after: issued.not_after,
      sealed_key: sealed.ciphertext,
      sealed_key_iv: sealed.iv,
      sealed_key_tag: sealed.tag
    })
    |> Repo.insert()
  end

  @doc """
  Issue the channel endpoint's server certificate under the active authority.

  The subject is the endpoint address as text and the subject alternative
  name is the same address, because the appliance dials an address literal and
  validates what it dialed.
  """
  @spec issue_endpoint_certificate(ChannelEndpoint.t(), DateTime.t()) ::
          {:ok, EndpointCertificate.t()} | {:error, Ecto.Changeset.t() | Certificate.reason()}
  def issue_endpoint_certificate(%ChannelEndpoint{} = endpoint, now \\ DateTime.utc_now()) do
    authority = active_authority!()
    authority_key = unseal_authority_key!(authority)

    key = KeyPair.generate()
    point = KeyPair.public_point(key)
    subject = ChannelEndpoint.address_text(endpoint.address)

    with {:ok, issued} <-
           Certificate.issue_under(
             {:channel_endpoint, endpoint.address},
             subject,
             point,
             authority.subject_common_name,
             authority_key,
             now
           ) do
      insert_endpoint_certificate(authority, endpoint, issued, key)
    end
  end

  defp insert_endpoint_certificate(authority, endpoint, issued, key) do
    sealed = Vault.seal(KeyPair.private_key_pem(key), EndpointCertificate.sealing_context())

    %EndpointCertificate{}
    |> EndpointCertificate.changeset(%{
      certificate_authority_id: authority.id,
      endpoint: ChannelEndpoint.to_string(endpoint),
      key_algorithm: Profile.key_algorithm(),
      signature_algorithm: Profile.signature_algorithm(),
      certificate_der: issued.der,
      serial: Integer.to_string(issued.serial),
      spki_fingerprint: issued.spki_fingerprint,
      not_before: issued.not_before,
      not_after: issued.not_after,
      sealed_key: sealed.ciphertext,
      sealed_key_iv: sealed.iv,
      sealed_key_tag: sealed.tag
    })
    |> Repo.insert()
  end

  @doc """
  Retire the current endpoint certificate and issue one for `endpoint`.

  The two happen together: an endpoint certificate for an endpoint the server
  no longer answers on is worse than none, because it looks current.
  """
  @spec reissue_endpoint_certificate(ChannelEndpoint.t(), DateTime.t()) ::
          {:ok, EndpointCertificate.t()} | {:error, term()}
  def reissue_endpoint_certificate(%ChannelEndpoint{} = endpoint, now \\ DateTime.utc_now()) do
    Repo.transaction(fn ->
      case active_endpoint_certificate() do
        nil ->
          :ok

        current ->
          current
          |> EndpointCertificate.changeset(%{retired_at: DateTime.truncate(now, :second)})
          |> Repo.update!()
      end

      case issue_endpoint_certificate(endpoint, now) do
        {:ok, issued} -> issued
        {:error, changeset} -> Repo.rollback(changeset)
      end
    end)
  end

  @doc """
  Issue a device certificate for a validated request.

  Everything in it comes from the profile, from the request's public key, and
  from the device identifier the request named. Nothing the request asked for
  reaches it, because a validated request asks for nothing.
  """
  @spec issue_device_certificate(CertificateAuthority.t(), binary(), String.t(), DateTime.t()) ::
          {:ok, Certificate.issued()} | {:error, Certificate.reason()}
  def issue_device_certificate(%CertificateAuthority{} = authority, point, device_id, now) do
    Certificate.issue_under(
      :device,
      device_id,
      point,
      authority.subject_common_name,
      unseal_authority_key!(authority),
      now
    )
  end

  @doc "An authority's certificate as PEM — the trust anchor a package carries."
  @spec authority_pem(CertificateAuthority.t()) :: String.t()
  def authority_pem(%CertificateAuthority{certificate_der: der}), do: Certificate.pem(der)

  @doc """
  Unseal an authority's signing key.

  Raises on a record that will not open: the key-encryption key has changed,
  or the row has been tampered with, and either way this server must not go on
  as though it could still sign.
  """
  @spec unseal_authority_key!(CertificateAuthority.t()) :: :public_key.private_key()
  def unseal_authority_key!(%CertificateAuthority{} = authority) do
    unseal!(authority, CertificateAuthority.sealing_context(), "certificate authority")
  end

  @doc "Unseal the channel endpoint certificate's key."
  @spec unseal_endpoint_key!(EndpointCertificate.t()) :: :public_key.private_key()
  def unseal_endpoint_key!(%EndpointCertificate{} = certificate) do
    unseal!(certificate, EndpointCertificate.sealing_context(), "channel endpoint certificate")
  end

  defp unseal!(record, context, described) do
    sealed = %{
      ciphertext: record.sealed_key,
      iv: record.sealed_key_iv,
      tag: record.sealed_key_tag
    }

    with {:ok, pem} <- Vault.open(sealed, context),
         {:ok, key} <- KeyPair.private_key_from_pem(pem) do
      key
    else
      _ ->
        raise "the #{described}'s sealed private key does not open under the configured " <>
                "key-encryption key"
    end
  end
end
