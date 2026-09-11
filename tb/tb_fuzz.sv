// tb_fuzz.sv — command-stream driven differential TB
// Stim format (whitespace-delimited tokens):
//   0 <en_hex> <base x16> <mask x16> <perm x16>   -> config load
//   1 <wr> <prot> <addr>                          -> single-beat txn
//  -1                                             -> end
// Results: "<wr> <prot> <addr> <resp>" per txn (resp: 0 OKAY / 3 DECERR)
`timescale 1ns/1ps
module tb_fuzz;
  localparam int AW=32, DW=32, IW=4;
  reg ACLK=0; always #5 ACLK = ~ACLK;
  reg ARESETn;

  reg  [15:0]        en; reg [16*AW-1:0] base, mask; reg [16*6-1:0] perm;
  reg                int_en=1'b0, clr_ovf=1'b0;
  wire               irq, log_ovf, log_rd_valid;
  wire [71:0]        log_rd_data;
  reg                log_rd_en=1'b0;

  reg          s_arvalid; wire s_arready;
  reg  [IW-1:0] s_arid; reg [AW-1:0] s_araddr; reg [2:0] s_arprot;
  wire [IW-1:0] s_rid; wire [DW-1:0] s_rdata; wire [1:0] s_rresp;
  wire s_rlast, s_rvalid; reg s_rready = 1'b1;
  reg          s_awvalid; wire s_awready;
  reg  [IW-1:0] s_awid; reg [AW-1:0] s_awaddr; reg [2:0] s_awprot;
  reg  [DW-1:0] s_wdata; reg [DW/8-1:0] s_wstrb; reg s_wlast, s_wvalid; wire s_wready;
  wire [IW-1:0] s_bid; wire [1:0] s_bresp; wire s_bvalid; reg s_bready = 1'b1;

  wire          m_arvalid; reg m_arready = 1'b1;
  wire [IW-1:0] m_arid; wire [AW-1:0] m_araddr; wire [2:0] m_arprot;
  wire [7:0]    m_arlen;
  reg           m_rvalid=1'b0; reg [IW-1:0] m_rid; reg [DW-1:0] m_rdata;
  wire          m_awvalid; reg m_awready = 1'b1; reg m_wready = 1'b1;
  wire [IW-1:0] m_awid; wire [AW-1:0] m_awaddr; wire [7:0] m_awlen;
  wire          m_wvalid;
  wire [DW-1:0] m_wdata; wire [DW/8-1:0] m_wstrb; wire m_wlast;
  reg           m_bvalid=1'b0; reg [IW-1:0] m_bid; wire m_bready;

  tz_firewall dut (
    .ACLK(ACLK), .ARESETn(ARESETn),
    .cfg_enable(en), .cfg_base(base), .cfg_mask(mask), .cfg_perm(perm),
    .cfg_int_en(int_en), .cfg_clr_ovf(clr_ovf),
    .log_rd_en(log_rd_en), .log_rd_data(log_rd_data),
    .log_rd_valid(log_rd_valid), .log_ovf(log_ovf), .irq(irq),
    .s_arid(s_arid), .s_araddr(s_araddr), .s_arlen(8'h0), .s_arsize(3'd2),
    .s_arburst(2'd1), .s_arprot(s_arprot), .s_arvalid(s_arvalid), .s_arready(s_arready),
    .s_rid(s_rid), .s_rdata(s_rdata), .s_rresp(s_rresp), .s_rlast(s_rlast),
    .s_rvalid(s_rvalid), .s_rready(s_rready),
    .s_awid(s_awid), .s_awaddr(s_awaddr), .s_awlen(8'h0), .s_awsize(3'd2),
    .s_awburst(2'd1), .s_awprot(s_awprot), .s_awvalid(s_awvalid), .s_awready(s_awready),
    .s_wdata(s_wdata), .s_wstrb(s_wstrb), .s_wlast(s_wlast),
    .s_wvalid(s_wvalid), .s_wready(s_wready),
    .s_bid(s_bid), .s_bresp(s_bresp), .s_bvalid(s_bvalid), .s_bready(s_bready),
    .m_arid(m_arid), .m_araddr(m_araddr), .m_arlen(m_arlen), .m_arsize(), .m_arburst(),
    .m_arprot(m_arprot), .m_arvalid(m_arvalid), .m_arready(m_arready),
    .m_rid(m_rid), .m_rdata(m_rdata), .m_rresp(2'b00), .m_rlast(1'b1),
    .m_rvalid(m_rvalid), .m_rready(),
    .m_awid(m_awid), .m_awaddr(m_awaddr), .m_awlen(m_awlen), .m_awsize(), .m_awburst(),
    .m_awprot(), .m_awvalid(m_awvalid), .m_awready(m_awready),
    .m_wdata(m_wdata), .m_wstrb(m_wstrb), .m_wlast(m_wlast),
    .m_wvalid(m_wvalid), .m_wready(m_wready),
    .m_bid(m_bid), .m_bresp(2'b00), .m_bvalid(m_bvalid), .m_bready(m_bready));

  // stub subordinate
  reg ar_d, w_d;
  always @(posedge ACLK or negedge ARESETn) begin
    if (!ARESETn) begin ar_d<=0; w_d<=0; m_rvalid<=0; m_bvalid<=0; end
    else begin
      if (m_arvalid && m_arready) begin ar_d<=1; m_rid<=m_arid; m_rdata<=32'hFACE_CAFE; end
      else ar_d<=0;
      m_rvalid <= ar_d;
      if (m_wvalid && m_wready && m_wlast) begin w_d<=1; m_bid<=m_awid; end
      else w_d<=0;
      m_bvalid <= w_d;
    end
  end

  integer stim_fd, res_fd, code, t;
  reg [1023:0] stim_name, res_name;
  reg [31:0]   tmp;

  task do_cfg;
    integer j;
    begin
      code = $fscanf(stim_fd, "%h", tmp); en = tmp[15:0];
      for (j=0;j<16;j=j+1) begin
        code = $fscanf(stim_fd, "%h", tmp); base[j*AW +: AW] = tmp;
      end
      for (j=0;j<16;j=j+1) begin
        code = $fscanf(stim_fd, "%h", tmp); mask[j*AW +: AW] = tmp;
      end
      for (j=0;j<16;j=j+1) begin
        code = $fscanf(stim_fd, "%h", tmp); perm[j*6 +: 6] = tmp[5:0];
      end
      #1;
    end
  endtask

  task do_txn(input wr, input [2:0] pr, input [AW-1:0] a);
    integer guard; logic [1:0] resp;
    begin
      resp = 2'b11; guard = 0;
      @(negedge ACLK);
      if (!wr) begin
        s_arid=1; s_araddr=a; s_arprot=pr; s_arvalid=1;
        @(posedge ACLK);
        while (!s_arready && guard<50) begin @(posedge ACLK); guard=guard+1; end
        s_arvalid=0;
        guard=0;
        while (!s_rvalid && guard<50) begin @(posedge ACLK); guard=guard+1; end
        resp = s_rresp; @(posedge ACLK);
      end else begin
        s_awid=2; s_awaddr=a; s_awprot=pr; s_awvalid=1;
        @(posedge ACLK);
        while (!s_awready && guard<50) begin @(posedge ACLK); guard=guard+1; end
        s_awvalid=0;
        @(negedge ACLK); s_wvalid=1; s_wdata=32'hBAD0_0001; s_wstrb={4{1'b1}}; s_wlast=1;
        @(posedge ACLK);
        while (!s_wready && guard<50) begin @(posedge ACLK); guard=guard+1; end
        @(negedge ACLK); s_wvalid=0; s_wlast=0;
        guard=0;
        while (!s_bvalid && guard<50) begin @(posedge ACLK); guard=guard+1; end
        resp = s_bresp; @(posedge ACLK);
      end
      $fdisplay(res_fd, "%0d %0d %08h %0d", wr, pr, a, resp);
    end
  endtask

  initial begin
    en=0; base=0; mask=0; perm=0;
    s_arvalid=0; s_awvalid=0; s_wvalid=0; s_wlast=0;
    s_arid=0; s_araddr=0; s_arprot=0; s_awid=0; s_awaddr=0; s_awprot=0;
    ARESETn=0;
    repeat(4) @(negedge ACLK);
    ARESETn=1;
    repeat(2) @(negedge ACLK);

    if (!$value$plusargs("STIM=%s", stim_name)) begin $display("NO STIM ARG"); $finish; end
    if (!$value$plusargs("RES=%s",  res_name))  begin $display("NO RES ARG");  $finish; end
    stim_fd = $fopen(stim_name, "r");
    res_fd  = $fopen(res_name, "w");
    if (stim_fd == 0) begin $display("NO STIM FILE"); $finish; end

    forever begin
      code = $fscanf(stim_fd, "%d", t);
      if (code <= 0 || t == -1) begin
        $fclose(res_fd); $fclose(stim_fd);
        $display("FUZZ DONE");
        $finish;
      end
      if (t == 0) do_cfg;
      else if (t == 1) begin : TXN
        reg       wr_;
        reg [2:0] pr_;
        reg [AW-1:0] a_;
        code = $fscanf(stim_fd, "%d", t); wr_ = t[0];
        code = $fscanf(stim_fd, "%d", t); pr_ = t[2:0];
        code = $fscanf(stim_fd, "%h", a_);
        do_txn(wr_, pr_, a_);
      end
    end
  end

  initial begin
    #500_000_000; $display("TIMEOUT"); $fclose(res_fd); $fatal;
  end
endmodule
