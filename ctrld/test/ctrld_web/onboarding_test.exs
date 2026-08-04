defmodule CtrldWeb.OnboardingTest do
  use CtrldWeb.ConnCase, async: true

  alias Ctrld.{Appliances, ChannelEndpoint, Configuration, PackageContract}

  setup %{conn: conn} do
    {conn, user, _token} = sign_in_administrator(conn)
    authority = authority_fixture()
    _endpoint_certificate = endpoint_certificate_fixture()
    %{conn: conn, user: user, authority: authority}
  end

  defp upload(pem) do
    path = Path.join(System.tmp_dir!(), "request-#{System.unique_integer([:positive])}.csr")
    File.write!(path, pem)
    on_exit(fn -> File.rm(path) end)

    %Plug.Upload{
      path: path,
      filename: "certificate.csr",
      content_type: "application/octet-stream"
    }
  end

  defp review(conn, pem) do
    post(conn, ~p"/appliances/onboard/review", %{"certificate_request" => upload(pem)})
  end

  defp issue(conn, pem, attributes) do
    post(conn, ~p"/appliances/onboard", %{
      "appliance" =>
        Map.merge(
          %{
            "certificate_request" => pem,
            "name" => "an appliance",
            "configuration" => Configuration.template()
          },
          attributes
        )
    })
  end

  describe "the upload page" do
    test "offers a multipart form", %{conn: conn} do
      html = conn |> get(~p"/appliances/onboard") |> html_response(200)
      assert html =~ ~s(id="request-form")
      assert html =~ ~s(enctype="multipart/form-data")
      assert html =~ ~s(name="certificate_request")
      assert html =~ "_csrf_token"
    end

    test "says so when there is no authority to sign with", %{conn: conn} do
      Ctrld.PKI.active_endpoint_certificate() |> Repo.delete!()
      Ctrld.PKI.active_authority() |> Repo.delete!()

      html = conn |> get(~p"/appliances/onboard") |> html_response(200)
      assert html =~ ~s(id="no-authority")
    end
  end

  describe "reading the request" do
    test "shows the fingerprint exactly as the contract renders it", %{conn: conn} do
      %{pem: pem} = csr_fixture()
      {:ok, request} = Ctrld.PKI.CSR.parse(pem)

      html = conn |> review(pem) |> html_response(200)

      assert html =~ request.spki_fingerprint
      assert Regex.match?(~r/^[0-9a-f]{64}$/, request.spki_fingerprint)
      refute html =~ String.upcase(request.spki_fingerprint)
      refute html =~ String.replace(request.spki_fingerprint, ~r/(..)(?=.)/, "\\1:")
    end

    test "shows the device identifier and the endpoint the appliance will dial", %{conn: conn} do
      %{pem: pem, device_id: device_id} = csr_fixture()

      html = conn |> review(pem) |> html_response(200)

      assert html =~ device_id
      assert html =~ ChannelEndpoint.to_string(ChannelEndpoint.configured!())
    end

    test "carries the request back in the form, so nothing is held between the posts", %{
      conn: conn
    } do
      %{pem: pem} = csr_fixture()
      html = conn |> review(pem) |> html_response(200)

      assert html =~ ~s(name="appliance[certificate_request]")
      assert html =~ "BEGIN CERTIFICATE REQUEST"
    end

    test "offers the configuration template to edit", %{conn: conn} do
      %{pem: pem} = csr_fixture()
      html = conn |> review(pem) |> html_response(200)
      assert html =~ ~s(name="appliance[configuration]")
      assert html =~ "&lt;configuration&gt;"
    end

    test "refuses bytes that are not a request, and says why", %{conn: conn} do
      conn = review(conn, "this is not a certificate signing request")

      assert redirected_to(conn) == ~p"/appliances/onboard"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "not PEM"
    end

    test "refuses a common name that is not a device identifier", %{conn: conn} do
      %{pem: pem} = csr_fixture(subject: "an appliance")
      conn = review(conn, pem)

      assert redirected_to(conn) == ~p"/appliances/onboard"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "device identifier"
    end

    test "refuses a request whose signature does not verify", %{conn: conn} do
      %{pem: pem} = csr_fixture()
      [{:CertificationRequest, der, _}] = :public_key.pem_decode(pem)

      {:CertificationRequest, info, algorithm, signature} =
        :public_key.der_decode(:CertificationRequest, der)

      <<first, rest::binary>> = signature

      forged =
        :public_key.der_encode(
          :CertificationRequest,
          {:CertificationRequest, info, algorithm, <<Bitwise.bxor(first, 0xFF), rest::binary>>}
        )

      conn =
        review(conn, :public_key.pem_encode([{:CertificationRequest, forged, :not_encrypted}]))

      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "signature"
    end

    test "refuses a file over the bound", %{conn: conn} do
      conn = review(conn, String.duplicate("x", Ctrld.PKI.CSR.maximum_bytes() + 1))
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "at most"
    end

    test "refuses a post with no file at all", %{conn: conn} do
      conn = post(conn, ~p"/appliances/onboard/review", %{})
      assert redirected_to(conn) == ~p"/appliances/onboard"
      assert Phoenix.Flash.get(conn.assigns.flash, :error) =~ "choose"
    end
  end

  describe "issuing" do
    test "signs, records the appliance, and lands on it", %{conn: conn} do
      %{pem: pem, device_id: device_id} = csr_fixture()

      conn = issue(conn, pem, %{"name" => "the first appliance"})

      assert redirected_to(conn) == ~p"/appliances/#{device_id}"
      assert Phoenix.Flash.get(conn.assigns.flash, :info) =~ device_id

      appliance = Appliances.get_appliance_by_device_id(device_id)
      assert appliance.name == "the first appliance"
      assert appliance.endpoint == ChannelEndpoint.to_string(ChannelEndpoint.configured!())
    end

    test "signs the key the request carried, under the authority", %{
      conn: conn,
      authority: authority
    } do
      %{pem: pem, device_id: device_id} = csr_fixture()
      issue(conn, pem, %{})

      appliance = Appliances.get_appliance_by_device_id(device_id)

      assert {:ok, _} =
               :public_key.pkix_path_validation(
                 authority.certificate_der,
                 [appliance.certificate_der],
                 []
               )
    end

    test "refuses a document that is not a configuration, re-rendering what was typed", %{
      conn: conn
    } do
      %{pem: pem} = csr_fixture()

      conn = issue(conn, pem, %{"configuration" => "<something-else/>", "name" => "kept"})

      html = html_response(conn, 200)
      assert html =~ ~s(id="step-review")
      assert html =~ "root element"
      assert html =~ ~s(value="kept")
      assert Appliances.list_appliances() == []
    end

    test "refuses a document declaring entities", %{conn: conn} do
      %{pem: pem} = csr_fixture()
      conn = issue(conn, pem, %{"configuration" => "<!DOCTYPE x><configuration/>"})

      assert html_response(conn, 200) =~ "entity"
      assert Appliances.list_appliances() == []
    end

    test "refuses a document over the package member's bound", %{conn: conn} do
      %{pem: pem} = csr_fixture()
      oversize = String.duplicate("x", Configuration.maximum_bytes() + 1)

      conn = issue(conn, pem, %{"configuration" => oversize})

      assert html_response(conn, 200) =~ "bounds it at"
      assert Appliances.list_appliances() == []
    end

    test "refuses an empty name", %{conn: conn} do
      %{pem: pem} = csr_fixture()
      conn = issue(conn, pem, %{"name" => ""})

      assert html_response(conn, 200) =~ ~s(id="step-review")
      assert Appliances.list_appliances() == []
    end

    test "refuses a second onboarding of one identity", %{conn: conn} do
      request = csr_fixture()
      issue(conn, request.pem, %{})
      conn = issue(conn, request.pem, %{"name" => "a duplicate"})

      assert html_response(conn, 200) =~ "already onboarded"
      assert length(Appliances.list_appliances()) == 1
    end

    test "a request that no longer parses goes back to the beginning", %{conn: conn} do
      conn = issue(conn, "not a request at all", %{})
      assert redirected_to(conn) == ~p"/appliances/onboard"
    end

    test "an incomplete form is refused rather than half-read", %{conn: conn} do
      for parameters <- [%{}, %{"appliance" => %{}}, %{"appliance" => %{"name" => "only"}}] do
        conn = post(conn, ~p"/appliances/onboard", parameters)
        assert redirected_to(conn) == ~p"/appliances/onboard"
      end

      assert Appliances.list_appliances() == []
    end

    test "posting at a server with no authority is a refusal, not a crash", %{conn: conn} do
      %{pem: pem} = csr_fixture()
      Ctrld.PKI.active_endpoint_certificate() |> Repo.delete!()
      Ctrld.PKI.active_authority() |> Repo.delete!()

      conn = issue(conn, pem, %{})

      assert html_response(conn, 200) =~ "holds no certificate authority"
      assert Appliances.list_appliances() == []
    end
  end

  describe "the package the interface hands out" do
    test "decodes against the contract and chains to this server's authority", %{
      conn: conn,
      authority: authority
    } do
      %{pem: pem, device_id: device_id} = csr_fixture()
      issue(conn, pem, %{"name" => "downloadable"})

      conn = get(conn, ~p"/appliances/#{device_id}/package.tar")

      assert response_content_type(conn, :tar) =~ "application/x-tar"
      assert ["attachment; filename=\"" <> _] = get_resp_header(conn, "content-disposition")

      assert {:ok, members} = PackageContract.decode(conn.resp_body)
      [{:Certificate, device_der, _}] = :public_key.pem_decode(members["device-certificate.pem"])

      assert {:ok, _} =
               :public_key.pkix_path_validation(authority.certificate_der, [device_der], [])
    end

    test "carries the endpoint and the document the administrator settled on", %{conn: conn} do
      %{pem: pem, device_id: device_id} = csr_fixture()
      issue(conn, pem, %{})

      conn = get(conn, ~p"/appliances/#{device_id}/package.tar")
      {:ok, members} = PackageContract.decode(conn.resp_body)

      assert members["management-endpoint"] ==
               ChannelEndpoint.to_string(ChannelEndpoint.configured!()) <> "\n"

      assert members["configuration.xml"] == Configuration.template()
    end

    test "an unknown appliance is a refusal rather than an empty archive", %{conn: conn} do
      conn = get(conn, ~p"/appliances/#{String.duplicate("0", 32)}/package.tar")
      assert conn.status == 404
    end
  end
end
