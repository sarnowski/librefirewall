defmodule Ctrld.ChannelEndpointTest do
  use ExUnit.Case, async: true

  alias Ctrld.ChannelEndpoint

  describe "parse/1" do
    test "accepts a dotted-quad address and a port" do
      assert {:ok, %ChannelEndpoint{address: {192, 0, 2, 10}, port: 8443}} =
               ChannelEndpoint.parse("192.0.2.10:8443")
    end

    test "accepts the boundary ports" do
      assert {:ok, %ChannelEndpoint{port: 1}} = ChannelEndpoint.parse("10.0.0.1:1")
      assert {:ok, %ChannelEndpoint{port: 65_535}} = ChannelEndpoint.parse("10.0.0.1:65535")
    end

    test "refuses an absent value" do
      assert ChannelEndpoint.parse(nil) == {:error, :absent}
      assert ChannelEndpoint.parse("  ") == {:error, :absent}
    end

    test "refuses anything that is not address and port" do
      for value <- ["192.0.2.10", "192.0.2.10:8443:1", "", ":8443"] do
        assert {:error, _reason} = ChannelEndpoint.parse(value)
      end
    end

    test "refuses a port outside the range" do
      assert ChannelEndpoint.parse("10.0.0.1:0") == {:error, {:port_out_of_range, 0}}
      assert ChannelEndpoint.parse("10.0.0.1:65536") == {:error, {:port_out_of_range, 65_536}}
      assert ChannelEndpoint.parse("10.0.0.1:-1") == {:error, {:port_out_of_range, -1}}
    end

    test "refuses a port that is not a number" do
      assert ChannelEndpoint.parse("10.0.0.1:https") == {:error, :malformed}
      assert ChannelEndpoint.parse("10.0.0.1:80x") == {:error, :malformed}
    end

    test "refuses a name, because there is no resolver on this path" do
      assert ChannelEndpoint.parse("management.example.com:8443") == {:error, :not_ipv4}
    end

    test "refuses a shortened or over-long address" do
      assert ChannelEndpoint.parse("10.1:8443") == {:error, :not_ipv4}
      assert ChannelEndpoint.parse("10.0.0.0.1:8443") == {:error, :not_ipv4}
      assert ChannelEndpoint.parse("300.0.0.1:8443") == {:error, :not_ipv4}
    end

    test "refuses an IPv6 literal" do
      assert {:error, _} = ChannelEndpoint.parse("::1:8443")
    end
  end

  describe "rendering" do
    test "round-trips through the package member's form" do
      for text <- ["192.0.2.10:8443", "10.0.0.1:1", "255.255.255.255:65535"] do
        {:ok, endpoint} = ChannelEndpoint.parse(text)
        assert ChannelEndpoint.to_string(endpoint) == text
      end
    end

    test "the address alone is what the endpoint certificate's subject carries" do
      {:ok, endpoint} = ChannelEndpoint.parse("192.0.2.10:8443")
      assert ChannelEndpoint.address_text(endpoint.address) == "192.0.2.10"
    end

    test "the rendering fits the package member's bound" do
      {:ok, endpoint} = ChannelEndpoint.parse("255.255.255.255:65535")
      assert byte_size(ChannelEndpoint.to_string(endpoint) <> "\n") <= 32
    end
  end

  describe "configured!/0" do
    test "returns the endpoint the deployment set" do
      assert %ChannelEndpoint{} = ChannelEndpoint.configured!()
    end
  end
end
