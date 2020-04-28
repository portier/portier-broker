#!/usr/bin/env ruby

# Fetch the list of top-level domains from IANA, and generate a Rust array.

require 'uri'
require 'net/http'

uri = URI('https://data.iana.org/TLD/tlds-alpha-by-domain.txt')
output = Net::HTTP.get(uri).lines
  .select { |line| !line.empty? and !line.start_with? '#' }
  .map { |line| "    \"#{line.strip.downcase}\"," }
  .join "\n"

output = <<EOF
// This file is generated from IANA data using `mktlds.rb`.

lazy_static::lazy_static! {
    pub static ref TLDS: std::collections::HashSet<&'static str> = {
        TLDS_LIST.iter().cloned().collect()
    };
}

const TLDS_LIST: &[&str] = &[
#{output}
];
EOF

output_path = File.join(__dir__, 'src/utils/tlds.rs')
File.write(output_path, output)
