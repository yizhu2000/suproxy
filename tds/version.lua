local _M={}
--- SqlServerVersionInfo class

_M={
  versionNumber = "", -- The full version string (e.g. "9.00.2047.00")
  major = nil, -- The major version (e.g. 9)
  minor = nil, -- The minor version (e.g. 0)
  build = nil, -- The build number (e.g. 2047)
  subBuild = nil, -- The sub-build number (e.g. 0)
  productName = nil, -- The product name (e.g. "SQL Server 2005")
  brandedVersion = nil, -- The branded version of the product (e.g. "2005")
  servicePackLevel = nil, -- The service pack level (e.g. "SP1")
  patched = nil, -- Whether patches have been applied since SP installation (true/false/nil)
  source = nil, -- The source of the version info (e.g. "SSRP", "SSNetLib")

  new = function(self,o)
    o = o or {}
    setmetatable(o, self)
    self.__index = self
    return o
  end,

  --- Sets the version using a version number string.
  --
  -- @param versionNumber a version number string (e.g. "9.00.1399.00")
  -- @param source a string indicating the source of the version info (e.g. "SSRP", "SSNetLib")
  SetVersionNumber = function(self, versionNumber, source)
    local major, minor, revision, subBuild
    if versionNumber:match( "^%d+%.%d+%.%d+.%d+" ) then
      major, minor, revision, subBuild = versionNumber:match( "^(%d+)%.(%d+)%.(%d+)" )
    elseif versionNumber:match( "^%d+%.%d+%.%d+" ) then
      major, minor, revision = versionNumber:match( "^(%d+)%.(%d+)%.(%d+)" )
    else
      print("%s: SetVersionNumber: versionNumber is not in correct format: %s", "MSSQL", versionNumber or "nil" )
    end

    self:SetVersion( major, minor, revision, subBuild, source )
  end,

  --- Sets the version using the individual numeric components of the version
  --  number.
  --
  -- @param source a string indicating the source of the version info (e.g. "SSRP", "SSNetLib")
  SetVersion = function(self, major, minor, build, subBuild, source)
    self.source = source
    -- make sure our version numbers all end up as valid numbers
    self.major, self.minor, self.build, self.subBuild =
      tonumber( major or 0 ), tonumber( minor or 0 ), tonumber( build or 0 ), tonumber( subBuild or 0 )

    self.versionNumber = string.format( "%u.%02u.%u.%02u", self.major, self.minor, self.build, self.subBuild )

    self:_ParseVersionInfo()
  end,

  --- Using the version number, determines the product version
  _InferProductVersion = function(self)

    local VERSION_LOOKUP_TABLE = {
      ["^6%.0"] = "6.0", ["^6%.5"] = "6.5", ["^7%.0"] = "7.0",
      ["^8%.0"] = "2000", ["^9%.0"] = "2005", ["^10%.0"] = "2008",
      ["^10%.50"] = "2008 R2", ["^11%.0"] = "2012", ["^12%.0"] = "2014",
      ["^13%.0"] = "2016", ["^14%.0"] = "2017", ["^15%.0"] = "2019"
    }

    local product = ""

    for m, v in pairs(VERSION_LOOKUP_TABLE) do
      if ( self.versionNumber:match(m) ) then
        product = v
        self.brandedVersion = product
        break
      end
    end

    self.productName = ("Microsoft SQL Server %s"):format(product)

  end,


  --- Returns a lookup table that maps revision numbers to service pack levels for
  --  the applicable SQL Server version (e.g. { {1600, "RTM"}, {2531, "SP1"} }).
  _GetSpLookupTable = function(self)

    -- Service pack lookup tables:
    -- For instances where a revised service pack was released (e.g. 2000 SP3a), we will include the
    -- build number for the original SP and the build number for the revision. However, leaving it
    -- like this would make it appear that subsequent builds were a patched version of the revision
    -- (e.g. a patch applied to 2000 SP3 that increased the build number to 780 would get displayed
    -- as "SP3a+", when it was actually SP3+). To avoid this, we will include an additional fake build
    -- number that combines the two.
    local SP_LOOKUP_TABLE = {
      ["6.5"] = {
        {201, "RTM"},
        {213, "SP1"},
        {240, "SP2"},
        {258, "SP3"},
        {281, "SP4"},
        {415, "SP5"},
        {416, "SP5a"},
        {417, "SP5/SP5a"},
      },

      ["7.0"] = {
        {623, "RTM"},
        {699, "SP1"},
        {842, "SP2"},
        {961, "SP3"},
        {1063, "SP4"},
      },

      ["2000"] = {
        {194, "RTM"},
        {384, "SP1"},
        {532, "SP2"},
        {534, "SP2"},
        {760, "SP3"},
        {766, "SP3a"},
        {767, "SP3/SP3a"},
        {2039, "SP4"},
      },

      ["2005"] = {
        {1399, "RTM"},
        {2047, "SP1"},
        {3042, "SP2"},
        {4035, "SP3"},
        {5000, "SP4"},
      },

      ["2008"] = {
        {1600, "RTM"},
        {2531, "SP1"},
        {4000, "SP2"},
        {5500, "SP3"},
        {6000, "SP4"},
      },

      ["2008 R2"] = {
        {1600, "RTM"},
        {2500, "SP1"},
        {4000, "SP2"},
        {6000, "SP3"},
      },

      ["2012"] = {
        {2100, "RTM"},
        {3000, "SP1"},
        {5058, "SP2"},
        {6020, "SP3"},
        {7001, "SP4"},
      },

      ["2014"] = {
        {2000, "RTM"},
        {4100, "SP1"},
        {5000, "SP2"},
        {6024, "SP3"},
      },

      ["2016"] = {
        {1601, "RTM"},
        {4001, "SP1"},
        {5026, "SP2"},
      },

      ["2017"] = {
        {1000, "RTM"},
        {3257, "CU18"},
      },

      ["2019"] = {
        {2000, "RTM"},
      },
    }


    if ( not self.brandedVersion ) then
      self:_InferProductVersion()
    end

    local spLookupTable = SP_LOOKUP_TABLE[self.brandedVersion]
    print("brandedVersion: %s, #lookup: %d", self.brandedVersion, spLookupTable and #spLookupTable or 0)

    return spLookupTable

  end,


  --- Processes version data to determine (if possible) the product version,
  --  service pack level and patch status.
  _ParseVersionInfo = function(self)

    local spLookupTable = self:_GetSpLookupTable()

    if spLookupTable then

      local spLookupItr = 0
      -- Loop through the service pack levels until we find one whose revision
      -- number is the same as or lower than our revision number.
      while spLookupItr < #spLookupTable do
        spLookupItr = spLookupItr + 1

        if (spLookupTable[ spLookupItr ][1] == self.build ) then
          spLookupItr = spLookupItr
          break
        elseif (spLookupTable[ spLookupItr ][1] > self.build ) then
          -- The target revision number is lower than the first release
          if spLookupItr == 1 then
            self.servicePackLevel = "Pre-RTM"
          else
            -- we went too far - it's the previous SP, but with patches applied
            spLookupItr = spLookupItr - 1
          end
          break
        end
      end

      -- Now that we've identified the proper service pack level:
      if self.servicePackLevel ~= "Pre-RTM" then
        self.servicePackLevel = spLookupTable[ spLookupItr ][2]

        if ( spLookupTable[ spLookupItr ][1] == self.build ) then
          self.patched = false
        else
          self.patched = true
        end
      end

      -- Clean up some of our inferences. If the source of our revision number
      -- was the SSRP (SQL Server Browser) response, we need to recognize its
      -- limitations:
      --  * Versions of SQL Server prior to 2005 are reported with the RTM build
      --    number, regardless of the actual version (e.g. SQL Server 2000 is
      --    always 8.00.194).
      --  * Versions of SQL Server starting with 2005 (and going through at least
      --    2008) do better but are still only reported with the build number as
      --    of the last service pack (e.g. SQL Server 2005 SP3 with patches is
      --    still reported as 9.00.4035.00).
      if ( self.source == "SSRP" ) then
        self.patched = nil

        if ( self.major <= 8 ) then
          self.servicePackLevel = nil
        end
      end
    end

    return true
  end,

  ---
  ToString = function(self)
    local rs = {}
    if self.productName then
      rs[#rs+1]= self.productName 
      if self.servicePackLevel then
        rs[#rs+1]= " " 
        rs[#rs+1]= self.servicePackLevel 
      end
      if self.patched then
        rs[#rs+1]= "+" 
      end
    end

    return table.concat(rs)
  end,

 
}

return _M