defmodule Ctrld.Repo do
  use Ecto.Repo,
    otp_app: :ctrld,
    adapter: Ecto.Adapters.Postgres
end
