defmodule Ctrld.PKI.CSRTest do
  use ExUnit.Case, async: true

  import Ctrld.Fixtures

  alias Ctrld.PKI.{CSR, KeyPair, Profile}

  describe "a request of the shape the appliance produces" do
    test "is accepted, and yields the identity it names" do
      %{pem: pem, key: key, device_id: device_id} = csr_fixture()

      assert {:ok, request} = CSR.parse(pem)
      assert request.device_id == device_id
      assert request.public_point == KeyPair.public_point(key)
      assert request.spki_fingerprint == KeyPair.fingerprint(KeyPair.public_point(key))
    end

    test "the fingerprint is 64 lowercase hexadecimal characters and nothing else" do
      %{pem: pem} = csr_fixture()
      {:ok, request} = CSR.parse(pem)

      assert String.length(request.spki_fingerprint) == 64
      assert Regex.match?(~r/^[0-9a-f]{64}$/, request.spki_fingerprint)
    end

    test "the request is re-emitted as one PEM structure with the right label" do
      %{pem: pem} = csr_fixture()
      {:ok, request} = CSR.parse(pem)

      assert [{:CertificationRequest, _der, :not_encrypted}] =
               :public_key.pem_decode(request.pem)

      assert String.starts_with?(request.pem, "-----BEGIN CERTIFICATE REQUEST-----")
    end
  end

  describe "refusals" do
    test "a file over the bound is refused before it is parsed" do
      oversize = String.duplicate("a", CSR.maximum_bytes() + 1)
      assert {:error, {:too_large, size}} = CSR.parse(oversize)
      assert size == CSR.maximum_bytes() + 1
    end

    test "bytes that are not PEM" do
      assert CSR.parse("not pem at all") == {:error, :not_pem}
      assert CSR.parse("") == {:error, :not_pem}
    end

    test "PEM carrying something other than a request" do
      key = KeyPair.generate()
      assert CSR.parse(KeyPair.private_key_pem(key)) == {:error, :wrong_pem_label}
    end

    test "more than one PEM structure" do
      %{pem: first} = csr_fixture()
      %{pem: second} = csr_fixture()
      assert CSR.parse(first <> second) == {:error, :multiple_pem_entries}
    end

    test "a PEM body that is not a well-formed request" do
      malformed =
        :public_key.pem_encode([{:CertificationRequest, <<0, 1, 2, 3, 4>>, :not_encrypted}])

      assert CSR.parse(malformed) == {:error, :malformed}
    end

    test "a common name that is not a device identifier" do
      for subject <- ["appliance one", "", String.duplicate("f", 31), String.duplicate("f", 33)] do
        %{pem: pem} = csr_fixture(subject: subject)
        assert CSR.parse(pem) == {:error, :common_name_not_a_device_id}
      end
    end

    test "an upper-case rendering of an identifier, because there is only one rendering" do
      %{pem: pem} = csr_fixture(subject: String.upcase(device_id()))
      assert CSR.parse(pem) == {:error, :common_name_not_a_device_id}
    end

    test "a request asking for extensions is refused rather than silently ignored" do
      extension_request =
        {:AttributePKCS_10, {1, 2, 840, 113_549, 1, 9, 14}, [{:asn1_OPENTYPE, <<48, 0>>}]}

      %{pem: pem} = csr_fixture(attributes: [extension_request])
      assert CSR.parse(pem) == {:error, :requests_extensions}
    end

    test "a signature that does not verify against the key the request carries" do
      %{pem: pem} = csr_fixture()
      [{:CertificationRequest, der, :not_encrypted}] = :public_key.pem_decode(pem)

      {:CertificationRequest, info, algorithm, signature} =
        :public_key.der_decode(:CertificationRequest, der)

      <<first, rest::binary>> = signature
      forged = <<Bitwise.bxor(first, 0xFF), rest::binary>>

      tampered =
        :public_key.der_encode(
          :CertificationRequest,
          {:CertificationRequest, info, algorithm, forged}
        )

      assert CSR.parse(
               :public_key.pem_encode([{:CertificationRequest, tampered, :not_encrypted}])
             ) ==
               {:error, :bad_signature}
    end

    test "a request signed over one key but carrying another" do
      %{pem: honest} = csr_fixture()
      %{pem: other} = csr_fixture()

      [{:CertificationRequest, honest_der, _}] = :public_key.pem_decode(honest)
      [{:CertificationRequest, other_der, _}] = :public_key.pem_decode(other)

      {:CertificationRequest, honest_info, algorithm, signature} =
        :public_key.der_decode(:CertificationRequest, honest_der)

      {:CertificationRequest, other_info, _, _} =
        :public_key.der_decode(:CertificationRequest, other_der)

      {:CertificationRequestInfo, v, subject, _key, attributes} = honest_info
      {:CertificationRequestInfo, _, _, other_key, _} = other_info
      swapped = {:CertificationRequestInfo, v, subject, other_key, attributes}

      substituted =
        :public_key.der_encode(
          :CertificationRequest,
          {:CertificationRequest, swapped, algorithm, signature}
        )

      assert CSR.parse(
               :public_key.pem_encode([{:CertificationRequest, substituted, :not_encrypted}])
             ) == {:error, :bad_signature}
    end

    test "an RSA request is refused on its signature algorithm" do
      assert CSR.parse(rsa_csr_fixture(:rsa)) ==
               {:error, {:unsupported_signature_algorithm, {1, 2, 840, 113_549, 1, 1, 11}}}
    end

    test "an RSA key claiming this profile's signature algorithm is refused on the key" do
      assert CSR.parse(rsa_csr_fixture(:profile)) ==
               {:error, {:unsupported_key_algorithm, {1, 2, 840, 113_549, 1, 1, 1}}}
    end

    test "a subject carrying more than a common name" do
      subject =
        {:rdnSequence,
         [
           [
             {:AttributeTypeAndValue, Profile.common_name_oid(), {:utf8String, device_id()}}
           ],
           [
             {:AttributeTypeAndValue, {2, 5, 4, 10}, {:utf8String, "an owner"}}
           ]
         ]}

      assert CSR.parse(odd_subject_csr_fixture(subject)) ==
               {:error, :subject_not_one_attribute}
    end

    test "a subject whose one attribute is not a common name" do
      subject =
        {:rdnSequence,
         [
           [
             {:AttributeTypeAndValue, {2, 5, 4, 10}, {:utf8String, "an owner"}}
           ]
         ]}

      assert CSR.parse(odd_subject_csr_fixture(subject)) == {:error, :subject_not_common_name}
    end

    test "a key on another curve" do
      key = :public_key.generate_key({:namedCurve, {1, 3, 132, 0, 34}})
      {:ok, pem} = build_request(key, device_id(), [], :sha384)

      assert {:error, reason} = CSR.parse(pem)
      assert reason in [{:unsupported_curve, {1, 3, 132, 0, 34}}, :bad_signature]
    end

    test "a request signed under another digest does not verify" do
      %{pem: pem} = csr_fixture(digest: :sha512)
      assert CSR.parse(pem) == {:error, :bad_signature}
    end

    test "every refusal renders as a sentence an administrator can act on" do
      reasons = [
        {:too_large, 99_999},
        :not_pem,
        :wrong_pem_label,
        :multiple_pem_entries,
        :malformed,
        {:unsupported_version, :v3},
        {:unsupported_signature_algorithm, {1, 2, 840, 113_549, 1, 1, 11}},
        {:unsupported_key_algorithm, {1, 2, 840, 113_549, 1, 1, 1}},
        {:unsupported_curve, {1, 3, 132, 0, 34}},
        :subject_not_one_attribute,
        :subject_not_common_name,
        :common_name_not_a_device_id,
        :requests_extensions,
        :bad_signature
      ]

      for reason <- reasons do
        described = CSR.describe(reason)
        assert is_binary(described)
        assert String.length(described) > 10
      end
    end
  end

  describe "arbitrary bytes" do
    test "never crash the parser, whatever they are" do
      for _ <- 1..200 do
        size = :rand.uniform(2048)
        assert {:error, _reason} = CSR.parse(:crypto.strong_rand_bytes(size))
      end
    end

    test "neither does truncating a real request at every length" do
      %{pem: pem} = csr_fixture()
      [{:CertificationRequest, der, :not_encrypted}] = :public_key.pem_decode(pem)

      for length <- 0..byte_size(der)//7 do
        truncated = binary_part(der, 0, length)

        wrapped =
          :public_key.pem_encode([{:CertificationRequest, truncated, :not_encrypted}])

        assert {:error, _reason} = CSR.parse(wrapped)
      end
    end

    test "nor does flipping one byte anywhere in a real request" do
      %{pem: pem} = csr_fixture()
      [{:CertificationRequest, der, :not_encrypted}] = :public_key.pem_decode(pem)

      for offset <- 0..(byte_size(der) - 1)//5 do
        <<before::binary-size(^offset), byte, rest::binary>> = der
        flipped = <<before::binary, Bitwise.bxor(byte, 0xFF), rest::binary>>

        result =
          CSR.parse(:public_key.pem_encode([{:CertificationRequest, flipped, :not_encrypted}]))

        assert match?({:error, _}, result) or match?({:ok, _}, result)
      end
    end
  end

  describe "the profile's device identifier" do
    test "is exactly 32 lowercase hexadecimal characters" do
      assert Profile.device_id?(String.duplicate("0", 32))
      assert Profile.device_id?("0123456789abcdef0123456789abcdef")
      refute Profile.device_id?("0123456789ABCDEF0123456789abcdef")
      refute Profile.device_id?(String.duplicate("0", 31))
      refute Profile.device_id?(String.duplicate("0", 33))
      refute Profile.device_id?("0123456789abcdef0123456789abcdeg")
      refute Profile.device_id?(nil)
      refute Profile.device_id?(:not_a_string)
    end
  end
end
