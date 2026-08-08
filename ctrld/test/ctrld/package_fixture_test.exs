defmodule Ctrld.PackageFixtureTest do
  @moduledoc """
  The writer against a committed archive the appliance's own suite reads.

  `Ctrld.PackageContract` holds this writer to the format's rules, and that
  catches a change that leaves the contract. It cannot catch a change that
  stays inside the contract and still moves the bytes — a different field
  width, a different padding byte, members emitted in another order — because
  the decoder would accept the result and so would the appliance's reader, and
  the two would go on agreeing while the artifact quietly changed under
  everything that had ever been asserted about it.

  So this test names one archive. The fixture is the package this writer
  produced from the inputs below; the appliance's `lfw-package` crate reads
  that same file as its own fixture, and this test asserts the writer still
  produces it byte for byte. The reproduction is possible at all because the
  writer takes the modification instant rather than reading a clock: the
  headers are the only place a build could differ from a build, and that field
  is an argument.

  A change to the archive's bytes therefore has to be made deliberately, in
  both components, by replacing the fixture — which is the moment somebody
  looks at whether the appliance's reader still admits it.
  """

  use ExUnit.Case, async: true

  alias Ctrld.{Package, PackageContract}

  @fixture Path.expand(
             "../../../datad/crates/package/fixtures/management-server-package.tar",
             __DIR__
           )

  # The instant the fixture's headers carry. Recorded here rather than read
  # back out of the archive: an expectation taken from the artifact it is
  # checking expects nothing.
  @modified_at ~U[2026-08-04 12:00:00Z]

  @endpoint "192.0.2.10:8443\n"

  setup do
    archive = File.read!(@fixture)
    {:ok, members} = PackageContract.decode(archive)
    %{archive: archive, members: members}
  end

  test "the committed fixture is one this writer still produces, byte for byte", %{
    archive: archive,
    members: members
  } do
    contents = %{
      device_certificate_pem: members["device-certificate.pem"],
      trust_anchor_pem: members["trust-anchor.pem"],
      management_endpoint: members["management-endpoint"],
      configuration_xml: members["configuration.xml"]
    }

    assert {:ok, rebuilt} = Package.build(contents, @modified_at)
    assert rebuilt == archive
  end

  test "the fixture carries what the appliance's reader is asserted to find", %{members: members} do
    assert Map.keys(members) |> Enum.sort() == Enum.sort(PackageContract.names())
    assert members["management-endpoint"] == @endpoint

    for name <- ["device-certificate.pem", "trust-anchor.pem"] do
      assert String.starts_with?(members[name], "-----BEGIN CERTIFICATE-----\n")
      assert [{:Certificate, der, :not_encrypted}] = :public_key.pem_decode(members[name])
      assert byte_size(der) > 0
    end
  end

  test "the fixture's device certificate is issued under its trust anchor", %{members: members} do
    [{:Certificate, device, :not_encrypted}] =
      :public_key.pem_decode(members["device-certificate.pem"])

    [{:Certificate, anchor, :not_encrypted}] = :public_key.pem_decode(members["trust-anchor.pem"])

    assert :public_key.pkix_is_issuer(device, anchor)
    assert {:ok, _chain} = :public_key.pkix_path_validation(anchor, [device], [])
  end

  test "no private key is committed beside the fixture" do
    beside = @fixture |> Path.dirname() |> File.ls!()

    assert Enum.sort(beside) == ["appliance-public-key.bin", "management-server-package.tar"]

    for name <- beside do
      contents = @fixture |> Path.dirname() |> Path.join(name) |> File.read!()
      refute String.contains?(contents, "PRIVATE KEY")
    end
  end
end
