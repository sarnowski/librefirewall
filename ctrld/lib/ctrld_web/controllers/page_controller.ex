defmodule CtrldWeb.PageController do
  use CtrldWeb, :controller

  def home(conn, _params) do
    render(conn, :home)
  end
end
