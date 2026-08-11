defmodule CtrldWeb.AuthorityLive do
  @moduledoc """
  The certificate authority this server signs with, and the channel endpoint's
  server certificate.

  Both are shown by their public facts alone. The private keys are sealed in
  the database and this interface has no way of asking for one — there is no
  export, because an authority key that can be exported through a web page is
  an authority key that will be.
  """

  use CtrldWeb, :live_view

  alias Ctrld.PKI

  @impl true
  def mount(_params, _session, socket) do
    {:ok,
     socket
     |> assign(:page_title, "Authority")
     |> assign(:authority, PKI.active_authority())
     |> assign(:endpoint_certificate, PKI.active_endpoint_certificate())}
  end

  @impl true
  def render(assigns) do
    ~H"""
    <Layouts.app flash={@flash} current_user={@current_user}>
      <h1 class="text-xl font-semibold">Authority</h1>

      <section id="authority" class="rounded-lg border border-base-300 p-4">
        <h2 class="font-semibold mb-3">Management certificate authority</h2>
        <p :if={is_nil(@authority)} class="text-sm opacity-70">
          This server holds no certificate authority.
        </p>
        <dl :if={@authority} class="grid grid-cols-[14rem_1fr] gap-y-2 text-sm">
          <dt class="opacity-70">Subject</dt>
          <dd>{@authority.subject_common_name}</dd>
          <dt class="opacity-70">SPKI fingerprint</dt>
          <dd id="authority-fingerprint" class="font-mono break-all">
            {@authority.spki_fingerprint}
          </dd>
          <dt class="opacity-70">Serial</dt>
          <dd class="font-mono break-all">{@authority.serial}</dd>
          <dt class="opacity-70">Key algorithm</dt>
          <dd>{@authority.key_algorithm}</dd>
          <dt class="opacity-70">Signature algorithm</dt>
          <dd>{@authority.signature_algorithm}</dd>
          <dt class="opacity-70">Valid</dt>
          <dd>{@authority.not_before} to {@authority.not_after}</dd>
        </dl>
        <p :if={@authority} class="text-xs opacity-60 mt-3">
          Every onboarded appliance pins this certificate as its trust anchor, and the anchor
          cannot be changed over the channel. Replacing it means visiting every appliance.
        </p>
      </section>

      <section id="endpoint-certificate" class="rounded-lg border border-base-300 p-4">
        <h2 class="font-semibold mb-3">Channel endpoint certificate</h2>
        <p :if={is_nil(@endpoint_certificate)} class="text-sm opacity-70">
          This server holds no channel endpoint certificate.
        </p>
        <dl :if={@endpoint_certificate} class="grid grid-cols-[14rem_1fr] gap-y-2 text-sm">
          <dt class="opacity-70">Endpoint</dt>
          <dd id="endpoint-certificate-endpoint" class="font-mono">
            {@endpoint_certificate.endpoint}
          </dd>
          <dt class="opacity-70">SPKI fingerprint</dt>
          <dd class="font-mono break-all">{@endpoint_certificate.spki_fingerprint}</dd>
          <dt class="opacity-70">Serial</dt>
          <dd class="font-mono break-all">{@endpoint_certificate.serial}</dd>
          <dt class="opacity-70">Key algorithm</dt>
          <dd>{@endpoint_certificate.key_algorithm}</dd>
          <dt class="opacity-70">Signature algorithm</dt>
          <dd>{@endpoint_certificate.signature_algorithm}</dd>
          <dt class="opacity-70">Valid</dt>
          <dd>{@endpoint_certificate.not_before} to {@endpoint_certificate.not_after}</dd>
        </dl>
        <p class="text-xs opacity-60 mt-3">
          The channel listener serves this certificate on that endpoint's port, and an appliance
          validates it against the trust anchor its package delivered and against the address
          literal it dialled — never a name. An appliance is told that address at onboarding and
          can never be told a different one afterwards.
        </p>
      </section>
    </Layouts.app>
    """
  end
end
