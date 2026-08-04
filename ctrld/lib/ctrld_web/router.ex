defmodule CtrldWeb.Router do
  use CtrldWeb, :router

  import CtrldWeb.UserAuth

  pipeline :browser do
    plug :accepts, ["html"]
    plug :fetch_session
    plug :fetch_live_flash
    plug :put_root_layout, html: {CtrldWeb.Layouts, :root}
    plug :protect_from_forgery
    plug :put_secure_browser_headers
    plug :fetch_current_user
  end

  scope "/", CtrldWeb do
    pipe_through [:browser, :redirect_if_authenticated]

    live_session :unauthenticated, on_mount: [{CtrldWeb.UserAuth, :mount_current_user}] do
      live "/sign-in", LoginLive, :new
    end

    post "/sign-in", SessionController, :create
  end

  scope "/", CtrldWeb do
    pipe_through [:browser, :require_authenticated_user]

    # The onboarding routes come first: `/appliances/onboard` must not be read
    # as an appliance whose device identifier is "onboard".
    get "/appliances/onboard", OnboardingController, :new
    post "/appliances/onboard/review", OnboardingController, :review
    post "/appliances/onboard", OnboardingController, :create

    live_session :authenticated, on_mount: [{CtrldWeb.UserAuth, :require_authenticated}] do
      live "/", ApplianceLive.Index, :index
      live "/appliances", ApplianceLive.Index, :index
      live "/appliances/:device_id", ApplianceLive.Show, :show
      live "/authority", AuthorityLive, :show
      live "/audit", AuditLive, :index
    end

    get "/appliances/:device_id/package.tar", PackageController, :show
    delete "/sign-out", SessionController, :delete
  end

  # Enable LiveDashboard and Swoosh mailbox preview in development
  if Application.compile_env(:ctrld, :dev_routes) do
    import Phoenix.LiveDashboard.Router

    scope "/dev" do
      pipe_through :browser

      live_dashboard "/dashboard", metrics: CtrldWeb.Telemetry
      forward "/mailbox", Plug.Swoosh.MailboxPreview
    end
  end
end
