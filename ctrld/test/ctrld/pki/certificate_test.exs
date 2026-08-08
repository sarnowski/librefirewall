defmodule Ctrld.PKI.CertificateTest do
  use ExUnit.Case, async: true

  import Ctrld.Fixtures

  alias Ctrld.PKI.{Certificate, KeyPair, Profile}

  setup do
    now = ~U[2026-08-04 12:00:00Z]
    {:ok, {issued, key}} = Certificate.create_authority("test authority", now)
    %{now: now, authority: issued, authority_key: key}
  end

  describe "the authority certificate" do
    test "is a version 3 certificate carrying its subject as its only attribute", %{
      authority: authority
    } do
      decoded = decode(authority.der)
      assert version(decoded) == :v3
      assert common_name(subject(decoded)) == "test authority"
      assert common_name(issuer(decoded)) == "test authority"
    end

    test "is signed with the profile's algorithm", %{authority: authority} do
      assert signature_algorithm(decode(authority.der)) == Profile.signature_oid()
    end

    test "carries a critical basic-constraints extension saying CA with path length zero", %{
      authority: authority
    } do
      assert {:Extension, _oid, true, {:BasicConstraints, true, 0}} =
               extension(authority.der, {2, 5, 29, 19})
    end

    test "carries key usage keyCertSign, critical, and no extended key usage", %{
      authority: authority
    } do
      assert {:Extension, _oid, true, [:keyCertSign]} = extension(authority.der, {2, 5, 29, 15})
      assert extension(authority.der, {2, 5, 29, 37}) == nil
      assert extension(authority.der, {2, 5, 29, 17}) == nil
    end

    test "is valid for exactly the profile's ten years", %{authority: authority, now: now} do
      assert authority.not_before == now
      assert authority.not_after == DateTime.shift(now, year: Profile.validity_years())
      assert authority.not_after.year - authority.not_before.year == 10
    end

    test "carries a serial of the profile's width", %{authority: authority} do
      assert authority.serial > 0
      assert authority.serial < Integer.pow(2, Profile.serial_bits())
      assert authority.serial >= Integer.pow(2, Profile.serial_bits() - 1)
    end

    test "verifies against itself, which is what self-signed means", %{authority: authority} do
      assert :public_key.pkix_is_self_signed(authority.der)
      assert :public_key.pkix_verify(authority.der, public_key(authority.der))
    end
  end

  describe "a device certificate" do
    setup %{authority: authority, authority_key: key, now: now} do
      device = device_id()
      subject_key = KeyPair.generate()

      {:ok, issued} =
        Certificate.issue_under(
          :device,
          device,
          KeyPair.public_point(subject_key),
          authority.subject_common_name,
          key,
          now
        )

      %{device: device, issued: issued, subject_key: subject_key}
    end

    test "names the device identifier as its only subject attribute", %{
      issued: issued,
      device: device
    } do
      assert common_name(subject(decode(issued.der))) == device
      assert issued.subject_common_name == device
    end

    test "is issued by the authority", %{issued: issued, authority: authority} do
      assert common_name(issuer(decode(issued.der))) == authority.subject_common_name
    end

    test "carries basic constraints CA:false, digitalSignature, and clientAuth", %{
      issued: issued
    } do
      assert {:Extension, _, true, {:BasicConstraints, false, :asn1_NOVALUE}} =
               extension(issued.der, {2, 5, 29, 19})

      assert {:Extension, _, true, [:digitalSignature]} = extension(issued.der, {2, 5, 29, 15})

      assert {:Extension, _, false, [{1, 3, 6, 1, 5, 5, 7, 3, 2}]} =
               extension(issued.der, {2, 5, 29, 37})
    end

    test "carries no subject alternative name", %{issued: issued} do
      assert extension(issued.der, {2, 5, 29, 17}) == nil
    end

    test "chains to the authority", %{issued: issued, authority: authority} do
      assert :public_key.pkix_verify(issued.der, public_key(authority.der))

      assert {:ok, _} =
               :public_key.pkix_path_validation(authority.der, [issued.der], [])
    end

    test "carries the subject's key and its fingerprint", %{
      issued: issued,
      subject_key: subject_key
    } do
      point = KeyPair.public_point(subject_key)
      assert issued.spki_fingerprint == KeyPair.fingerprint(point)
    end

    test "two issuances carry different serials" do
      assert Certificate.serial() != Certificate.serial()
    end
  end

  describe "the channel endpoint certificate" do
    setup %{authority: authority, authority_key: key, now: now} do
      subject_key = KeyPair.generate()

      {:ok, issued} =
        Certificate.issue_under(
          {:channel_endpoint, {192, 0, 2, 10}},
          "192.0.2.10",
          KeyPair.public_point(subject_key),
          authority.subject_common_name,
          key,
          now
        )

      %{issued: issued}
    end

    test "names the endpoint address as its subject", %{issued: issued} do
      assert common_name(subject(decode(issued.der))) == "192.0.2.10"
    end

    test "carries the endpoint address as an iPAddress subject alternative name", %{
      issued: issued
    } do
      assert {:Extension, _, false, [{:iPAddress, <<192, 0, 2, 10>>}]} =
               extension(issued.der, {2, 5, 29, 17})
    end

    test "carries serverAuth rather than clientAuth", %{issued: issued} do
      assert {:Extension, _, false, [{1, 3, 6, 1, 5, 5, 7, 3, 1}]} =
               extension(issued.der, {2, 5, 29, 37})
    end

    test "chains to the authority", %{issued: issued, authority: authority} do
      assert :public_key.pkix_verify(issued.der, public_key(authority.der))
    end
  end

  describe "validity encoding" do
    test "uses UTCTime through 2049 and GeneralizedTime from 2050" do
      {:ok, {through, _}} = Certificate.create_authority("early", ~U[2030-01-01 00:00:00Z])
      {:ok, {beyond, _}} = Certificate.create_authority("late", ~U[2045-01-01 00:00:00Z])

      assert {:Validity, {:utcTime, _}, {:utcTime, _}} = validity(decode(through.der))
      assert {:Validity, {:utcTime, _}, {:generalTime, _}} = validity(decode(beyond.der))
    end

    test "a leap day does not produce a date the calendar does not have" do
      {:ok, {issued, _}} = Certificate.create_authority("leap", ~U[2028-02-29 00:00:00Z])
      assert issued.not_after.month == 2
      assert issued.not_after.day == 28
      assert issued.not_after.year == 2038
    end
  end

  describe "the profile's bound on a certificate's DER" do
    test "everything this profile issues is well inside it", %{
      authority: authority,
      authority_key: key,
      now: now
    } do
      bound = Profile.max_certificate_der_bytes()
      subject_key = KeyPair.generate()

      {:ok, device} =
        Certificate.issue_under(
          :device,
          device_id(),
          KeyPair.public_point(subject_key),
          authority.subject_common_name,
          key,
          now
        )

      {:ok, endpoint} =
        Certificate.issue_under(
          {:channel_endpoint, {192, 0, 2, 10}},
          "192.0.2.10",
          KeyPair.public_point(subject_key),
          authority.subject_common_name,
          key,
          now
        )

      for issued <- [authority, device, endpoint] do
        assert byte_size(issued.der) <= bound
      end
    end

    test "a subject that would carry a certificate past it is refused rather than signed", %{
      now: now
    } do
      bound = Profile.max_certificate_der_bytes()
      assert {:error, reason} = Certificate.create_authority(String.duplicate("n", bound), now)
      assert {:certificate_too_long, _subject, size, ^bound} = reason
      assert size > bound
      assert Certificate.describe(reason) =~ "shorten the subject name"
    end

    test "an end-entity certificate is refused on the same rule", %{
      authority: authority,
      authority_key: key,
      now: now
    } do
      bound = Profile.max_certificate_der_bytes()
      subject_key = KeyPair.generate()

      assert {:error, {:certificate_too_long, _subject, size, ^bound}} =
               Certificate.issue_under(
                 :device,
                 String.duplicate("d", bound),
                 KeyPair.public_point(subject_key),
                 authority.subject_common_name,
                 key,
                 now
               )

      assert size > bound
    end
  end

  describe "PEM encoding" do
    test "is one CERTIFICATE structure with nothing around it", %{authority: authority} do
      pem = Certificate.pem(authority.der)
      assert String.starts_with?(pem, "-----BEGIN CERTIFICATE-----")
      assert [{:Certificate, der, :not_encrypted}] = :public_key.pem_decode(pem)
      assert der == authority.der
    end
  end

  defp decode(der), do: :public_key.pkix_decode_cert(der, :otp)

  defp tbs({:OTPCertificate, tbs, _algorithm, _signature}), do: tbs

  defp version(certificate), do: certificate |> tbs() |> elem(1)
  defp signature_algorithm(certificate), do: certificate |> tbs() |> elem(3) |> elem(1)
  defp issuer(certificate), do: certificate |> tbs() |> elem(4)
  defp validity(certificate), do: certificate |> tbs() |> elem(5)
  defp subject(certificate), do: certificate |> tbs() |> elem(6)

  defp common_name({:rdnSequence, [[{:AttributeTypeAndValue, _oid, {_type, name}}]]}),
    do: to_string(name)

  defp public_key(der) do
    {:OTPSubjectPublicKeyInfo, algorithm, point} = der |> decode() |> tbs() |> elem(7)
    {:PublicKeyAlgorithm, _oid, parameters} = algorithm
    {point, parameters}
  end

  defp extension(der, oid) do
    der
    |> decode()
    |> tbs()
    |> elem(10)
    |> Enum.find(fn {:Extension, extension_oid, _critical, _value} -> extension_oid == oid end)
  end
end
