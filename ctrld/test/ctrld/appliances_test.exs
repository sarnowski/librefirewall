defmodule Ctrld.AppliancesTest do
  use Ctrld.DataCase, async: true

  alias Ctrld.Appliances.ConfigurationVersion
  alias Ctrld.{Appliances, Audit, ChannelEndpoint, Configuration, PackageContract, PKI}
  alias Ctrld.PKI.CSR

  defp onboard(overrides \\ %{}) do
    _authority = PKI.active_authority() || authority_fixture()
    actor = Map.get_lazy(overrides, :actor, &administrator_fixture/0)
    %{pem: pem} = Map.get_lazy(overrides, :request, fn -> csr_fixture() end)
    {:ok, request} = CSR.parse(pem)

    attributes =
      Map.merge(
        %{
          name: "an appliance",
          configuration: Configuration.template(),
          endpoint: ChannelEndpoint.configured!(),
          actor: actor,
          received_at: DateTime.truncate(DateTime.utc_now(), :second)
        },
        Map.drop(overrides, [:request])
      )

    {Appliances.onboard(request, attributes), request, actor}
  end

  describe "onboarding" do
    test "records the appliance with the identity the request named" do
      {{:ok, %{appliance: appliance}}, request, actor} = onboard()

      assert appliance.device_id == request.device_id
      assert appliance.spki_fingerprint == request.spki_fingerprint
      assert appliance.name == "an appliance"
      assert appliance.onboarded_by_id == actor.id
      assert appliance.endpoint == ChannelEndpoint.to_string(ChannelEndpoint.configured!())
    end

    test "issues a certificate that chains to the authority" do
      authority = authority_fixture()
      {{:ok, %{appliance: appliance}}, _request, _actor} = onboard()

      assert {:ok, _} =
               :public_key.pkix_path_validation(
                 authority.certificate_der,
                 [appliance.certificate_der],
                 []
               )
    end

    test "records the document as generation 1 with its digest" do
      {{:ok, %{appliance: appliance}}, _request, actor} = onboard()

      [version] = Repo.all(ConfigurationVersion)
      assert version.appliance_id == appliance.id
      assert version.generation == 1
      assert version.document == Configuration.template()
      assert version.document_sha256 == ConfigurationVersion.digest(Configuration.template())
      assert version.author_id == actor.id
    end

    test "writes an audit record naming what was issued" do
      {{:ok, %{appliance: appliance}}, _request, actor} = onboard()

      [event] = Audit.list_events_for("appliance", appliance.device_id)
      assert event.action == "appliance.onboarded"
      assert event.actor_email == actor.email
      assert event.detail["spki_fingerprint"] == appliance.spki_fingerprint
      assert event.detail["certificate_serial"] == appliance.certificate_serial
    end

    test "returns a package that decodes against the contract" do
      {{:ok, %{package: package}}, _request, _actor} = onboard()

      assert {:ok, members} = PackageContract.decode(package)
      assert Map.keys(members) |> Enum.sort() == Enum.sort(PackageContract.names())
    end

    test "the package carries the appliance's own certificate and the anchor" do
      authority = authority_fixture()
      {{:ok, %{appliance: appliance, package: package}}, request, _actor} = onboard()
      {:ok, members} = PackageContract.decode(package)

      assert [{:Certificate, device_der, _}] =
               :public_key.pem_decode(members["device-certificate.pem"])

      assert device_der == appliance.certificate_der

      assert [{:Certificate, anchor_der, _}] =
               :public_key.pem_decode(members["trust-anchor.pem"])

      assert anchor_der == authority.certificate_der

      assert {:ok, _} = :public_key.pkix_path_validation(anchor_der, [device_der], [])
      assert subject_common_name(device_der) == request.device_id
    end

    test "the package carries the endpoint as one line and the document as given" do
      {{:ok, %{package: package}}, _request, _actor} = onboard()
      {:ok, members} = PackageContract.decode(package)

      endpoint = ChannelEndpoint.to_string(ChannelEndpoint.configured!())
      assert members["management-endpoint"] == endpoint <> "\n"
      assert members["configuration.xml"] == Configuration.template()
    end

    test "refuses a document this server can already tell is wrong, and issues nothing" do
      _authority = authority_fixture()
      {result, _request, _actor} = onboard(%{configuration: "<not-a-configuration/>"})

      assert {:error, {:wrong_root, "not-a-configuration"}} = result
      assert Appliances.list_appliances() == []
      assert Repo.all(ConfigurationVersion) == []
    end

    test "refuses a second request for an identity already onboarded" do
      _authority = authority_fixture()
      request = csr_fixture()
      {{:ok, _}, _request, _actor} = onboard(%{request: request})
      {result, _request, _actor} = onboard(%{request: request})

      assert result == {:error, :already_onboarded}
      assert length(Appliances.list_appliances()) == 1
    end

    test "refuses a name the schema will not take, and issues nothing" do
      _authority = authority_fixture()
      {result, _request, _actor} = onboard(%{name: String.duplicate("n", 200)})

      assert {:error, %Ecto.Changeset{}} = result
      assert Appliances.list_appliances() == []
      assert Audit.list_events(10) == []
    end
  end

  describe "the inventory" do
    test "shows only what the server can evidence" do
      {{:ok, %{appliance: appliance}}, _request, _actor} = onboard()
      assert Appliances.status(appliance) == :onboarded
    end

    test "lists appliances newest first" do
      _authority = authority_fixture()
      {{:ok, %{appliance: first}}, _, _} = onboard(%{name: "first"})
      {{:ok, %{appliance: second}}, _, _} = onboard(%{name: "second"})

      assert Enum.map(Appliances.list_appliances(), & &1.id) == [second.id, first.id]
    end

    test "one appliance is findable by the device identifier its certificate names" do
      {{:ok, %{appliance: appliance}}, _request, _actor} = onboard()
      assert Appliances.get_appliance_by_device_id(appliance.device_id).id == appliance.id
      refute Appliances.get_appliance_by_device_id("0" |> String.duplicate(32))
    end
  end

  describe "recomposing the package" do
    test "produces the same bytes as the issuance did" do
      {{:ok, %{appliance: appliance, package: issued}}, _request, _actor} = onboard()
      assert {:ok, ^issued} = Appliances.package(appliance)
    end

    test "produces the same bytes every time, so a re-download is not a new artifact" do
      {{:ok, %{appliance: appliance}}, _request, _actor} = onboard()
      assert Appliances.package(appliance) == Appliances.package(appliance)
    end
  end

  defp subject_common_name(der) do
    {:OTPCertificate, tbs, _algorithm, _signature} = :public_key.pkix_decode_cert(der, :otp)
    {:rdnSequence, [[{:AttributeTypeAndValue, _oid, {_type, name}}]]} = elem(tbs, 6)
    to_string(name)
  end
end
