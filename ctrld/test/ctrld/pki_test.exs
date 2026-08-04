defmodule Ctrld.PKITest do
  use Ctrld.DataCase, async: true

  alias Ctrld.PKI
  alias Ctrld.PKI.{CertificateAuthority, EndpointCertificate, KeyPair, Profile}
  alias Ctrld.{ChannelEndpoint, Vault}

  describe "creating the authority" do
    test "records the algorithm as a field rather than assuming it" do
      authority = authority_fixture()
      assert authority.key_algorithm == Profile.key_algorithm()
      assert authority.signature_algorithm == Profile.signature_algorithm()
    end

    test "records the facts a reader needs without opening anything" do
      authority = authority_fixture("an authority")
      assert authority.subject_common_name == "an authority"
      assert Regex.match?(~r/^[0-9a-f]{64}$/, authority.spki_fingerprint)
      assert String.to_integer(authority.serial) > 0
      assert authority.not_after.year - authority.not_before.year == Profile.validity_years()
    end

    test "stores the private key sealed and nothing else" do
      authority = authority_fixture()

      refute authority.sealed_key == nil
      assert byte_size(authority.sealed_key_iv) == 12
      assert byte_size(authority.sealed_key_tag) == 16
      refute String.contains?(authority.sealed_key, "PRIVATE KEY")
    end

    test "the sealed key opens only under this table's context" do
      authority = authority_fixture()

      sealed = %{
        ciphertext: authority.sealed_key,
        iv: authority.sealed_key_iv,
        tag: authority.sealed_key_tag
      }

      assert {:ok, pem} = Vault.open(sealed, CertificateAuthority.sealing_context())
      assert String.contains?(pem, "EC PRIVATE KEY")
      assert Vault.open(sealed, EndpointCertificate.sealing_context()) == :error
    end

    test "the unsealed key is the one the certificate was signed with" do
      authority = authority_fixture()
      key = PKI.unseal_authority_key!(authority)

      assert :public_key.pkix_verify(
               authority.certificate_der,
               {{:ECPoint, KeyPair.public_point(key)}, {:namedCurve, Profile.curve_oid()}}
             )
    end

    test "there is at most one active authority" do
      _first = authority_fixture()
      assert {:error, changeset} = PKI.create_authority("a second")
      refute changeset.valid?
    end

    test "active_authority!/0 refuses when there is none" do
      assert_raise RuntimeError, ~r/no active certificate authority/, &PKI.active_authority!/0
    end
  end

  describe "the channel endpoint certificate" do
    setup do
      %{authority: authority_fixture()}
    end

    test "is issued under the authority for the configured endpoint" do
      certificate = endpoint_certificate_fixture()
      assert certificate.endpoint == ChannelEndpoint.to_string(ChannelEndpoint.configured!())
      assert certificate.key_algorithm == Profile.key_algorithm()
    end

    test "chains to the authority", %{authority: authority} do
      certificate = endpoint_certificate_fixture()

      assert {:ok, _} =
               :public_key.pkix_path_validation(
                 authority.certificate_der,
                 [certificate.certificate_der],
                 []
               )
    end

    test "its key is sealed under its own context and opens" do
      certificate = endpoint_certificate_fixture()
      key = PKI.unseal_endpoint_key!(certificate)

      assert :public_key.pkix_verify(
               certificate.certificate_der,
               {{:ECPoint,
                 KeyPair.public_point(PKI.unseal_authority_key!(PKI.active_authority()))},
                {:namedCurve, Profile.curve_oid()}}
             )

      assert {:ECPrivateKey, _, _, _, _, _} = key
    end

    test "re-issuing retires the previous one, so only one is ever current" do
      first = endpoint_certificate_fixture()
      {:ok, second} = PKI.reissue_endpoint_certificate(ChannelEndpoint.configured!())

      assert PKI.active_endpoint_certificate().id == second.id
      assert Repo.get(EndpointCertificate, first.id).retired_at
      refute second.id == first.id
    end
  end

  describe "issuing a device certificate" do
    test "signs the key the request carried, under the device identifier it named" do
      authority = authority_fixture()
      %{pem: pem} = csr_fixture()
      {:ok, request} = Ctrld.PKI.CSR.parse(pem)

      issued =
        PKI.issue_device_certificate(
          authority,
          request.public_point,
          request.device_id,
          DateTime.utc_now()
        )

      assert issued.subject_common_name == request.device_id
      assert issued.spki_fingerprint == request.spki_fingerprint

      assert {:ok, _} =
               :public_key.pkix_path_validation(authority.certificate_der, [issued.der], [])
    end
  end
end
