defmodule Oauth.Mixfile do
  use Mix.Project

  def project do
    [app: :oauth,
     version: "1.5.0",
     description: description,
     package: package,
     deps: []]
  end

  defp description do
    """
    An Erlang OAuth 1.0 implementation
    """
  end

  defp package do
    [files: ~w(src, License.txt, Makefile, EMakefile),
     contributors: ["Tim Fletcher"],
     licenses: ["MIT"],
     links: %{"GitHub" => "https://github.com/tim/erlang-oauth"}]
  end
end

