defmodule CtrldWeb.PackageController do
  @moduledoc """
  Downloading an appliance's onboarding package.

  The archive is recomposed from what is stored rather than kept, so a
  download is always the package the stored facts describe and there is no
  second copy of them to go stale. Every download is audited: the package
  carries an appliance's identity, and who took a copy of it is part of the
  record.
  """

  use CtrldWeb, :controller

  alias Ctrld.{Appliances, Audit, Package}

  def show(conn, %{"device_id" => device_id}) do
    case Appliances.get_appliance_by_device_id(device_id) do
      nil ->
        conn |> put_status(:not_found) |> text("no such appliance")

      appliance ->
        deliver(conn, appliance)
    end
  end

  defp deliver(conn, appliance) do
    case Appliances.package(appliance) do
      {:ok, bytes} ->
        actor = conn.assigns.current_user

        Audit.write!(%{
          actor_id: actor.id,
          actor_email: actor.email,
          action: "package.downloaded",
          subject_type: "appliance",
          subject_id: appliance.device_id,
          detail: %{"bytes" => byte_size(bytes)}
        })

        conn
        # No charset: the archive is bytes, and a text encoding on it would be
        # a claim about content this server never looks inside.
        |> put_resp_content_type("application/x-tar", nil)
        |> put_resp_header(
          "content-disposition",
          ~s(attachment; filename="#{appliance.device_id}.tar")
        )
        |> send_resp(200, bytes)

      {:error, reason} ->
        conn
        |> put_status(:unprocessable_entity)
        |> text("the package could not be composed: " <> Package.describe(reason))
    end
  end
end
