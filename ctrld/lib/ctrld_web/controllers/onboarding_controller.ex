defmodule CtrldWeb.OnboardingController do
  @moduledoc """
  Onboarding an appliance, in two ordinary form posts.

  It is a controller and not a LiveView deliberately. Nothing about this flow
  is live — a file is chosen, a fingerprint is compared by eye, a document is
  edited, a certificate is signed — so the liveness would buy nothing, and two
  plain posts cost nothing to drive from a script, which is how the whole flow
  gets exercised against a running server rather than only against a test
  harness. The sign-in page already works this way for the same reason.

  There is no state between the two posts. The review page carries the
  uploaded request back in the form, and the second post parses it from
  scratch and derives the identity again — so the fingerprint an administrator
  compared and the key that gets signed are the same bytes read the same way,
  and nothing is trusted across the hop.
  """

  use CtrldWeb, :controller

  alias Ctrld.{Appliances, ChannelEndpoint, Configuration, Package, PKI}
  alias Ctrld.PKI.{Certificate, CSR}

  def new(conn, _params) do
    render(conn, :new,
      page_title: "Onboard an appliance",
      authority: PKI.active_authority(),
      maximum_bytes: CSR.maximum_bytes()
    )
  end

  def review(conn, %{"certificate_request" => %Plug.Upload{path: path}}) do
    case path |> File.read!() |> CSR.parse() do
      {:ok, request} -> render_review(conn, request, "", Configuration.template())
      {:error, reason} -> refuse(conn, CSR.describe(reason))
    end
  end

  def review(conn, _params), do: refuse(conn, "choose a certificate signing request first")

  def create(conn, %{
        "appliance" => %{
          "certificate_request" => pem,
          "name" => name,
          "configuration" => configuration
        }
      }) do
    with {:ok, request} <- CSR.parse(pem),
         {:ok, %{appliance: appliance}} <- onboard(conn, request, name, configuration) do
      conn
      |> put_flash(:info, "Issued a certificate for #{appliance.device_id}.")
      |> redirect(to: ~p"/appliances/#{appliance.device_id}")
    else
      {:error, reason} -> reject(conn, pem, name, configuration, reason)
    end
  end

  def create(conn, _params), do: refuse(conn, "the form was incomplete")

  defp onboard(conn, request, name, configuration) do
    Appliances.onboard(request, %{
      name: name,
      configuration: configuration,
      endpoint: ChannelEndpoint.configured!(),
      actor: conn.assigns.current_user,
      received_at: DateTime.truncate(DateTime.utc_now(), :second)
    })
  end

  # A refusal on the second post re-renders the review page with what the
  # administrator had, so a rejected document is corrected rather than retyped.
  # A request that no longer parses cannot be reviewed at all, so that one goes
  # back to the beginning.
  defp reject(conn, pem, name, configuration, reason) do
    case CSR.parse(pem) do
      {:ok, request} ->
        conn
        |> put_flash(:error, describe(reason))
        |> render_review(request, name, configuration)

      {:error, request_reason} ->
        refuse(conn, CSR.describe(request_reason))
    end
  end

  defp render_review(conn, request, name, configuration) do
    render(conn, :review,
      page_title: "Onboard an appliance",
      request: request,
      name: name,
      configuration: configuration,
      endpoint: ChannelEndpoint.configured!(),
      endpoint_certificate: PKI.active_endpoint_certificate(),
      authority: PKI.active_authority()
    )
  end

  defp refuse(conn, message) do
    conn
    |> put_flash(:error, message)
    |> redirect(to: ~p"/appliances/onboard")
  end

  defp describe(%Ecto.Changeset{} = changeset) do
    changeset
    |> Ecto.Changeset.traverse_errors(fn {message, _options} -> message end)
    |> Enum.map_join("; ", fn {field, messages} -> "#{field} #{Enum.join(messages, ", ")}" end)
  end

  defp describe(:already_onboarded = reason), do: Appliances.describe(reason)
  defp describe(:no_authority = reason), do: Appliances.describe(reason)
  defp describe({:member_too_large, _, _, _} = reason), do: Package.describe(reason)

  defp describe({:certificate_too_long, _, _, _} = reason),
    do: Certificate.describe(reason)

  defp describe(reason), do: Configuration.describe(reason)
end
