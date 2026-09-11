// tzf_faultlog.sv — fault-log bank + timestamp + interrupt (MICROSPEC SEC 4)
module tzf_faultlog #(
  parameter int LOG_DEPTH  = 8,
  parameter int ADDR_WIDTH = 32,
  parameter int TS_WIDTH   = 32,
  parameter int REGION_W   = 4,
  localparam int ENTRY_W = TS_WIDTH + ADDR_WIDTH + 2 + 2 + REGION_W
)(
  input  wire                   clk,
  input  wire                   rst_n,
  // push side
  input  wire                   push_i,
  input  wire [ADDR_WIDTH-1:0]  push_addr,
  input  wire [1:0]             push_prot,    // AxPROT[2:1] {inst, ns}
  input  wire [1:0]             push_op,      // 00=R 01=W 10=X
  input  wire [REGION_W-1:0]    push_region,  // all-ones = no-match
  // read/pop side (config bus)
  input  wire                   rd_en,
  output wire [ENTRY_W-1:0]     rd_data,
  output wire                   rd_valid,     // head valid
  output wire [$clog2(LOG_DEPTH+1)-1:0] cnt_o,  // occupancy (formal/observability)
  output wire [TS_WIDTH-1:0]     ts_o,          // free-running counter view
  output reg                    ovf_sticky,
  input  wire                   ovf_clr,
  input  wire                   int_en,
  output wire                   irq
);
  localparam int PTR_W = (LOG_DEPTH <= 1) ? 1 : $clog2(LOG_DEPTH);
  localparam [PTR_W:0] LOG_DEPTH_W = LOG_DEPTH[PTR_W:0];

  reg [TS_WIDTH-1:0] ts_cnt;
  always @(posedge clk or negedge rst_n)
    if (!rst_n) ts_cnt <= {TS_WIDTH{1'b0}};
    else        ts_cnt <= ts_cnt + {{(TS_WIDTH-1){1'b0}}, 1'b1};

  reg [ENTRY_W-1:0] entries [0:LOG_DEPTH-1];
  reg [PTR_W-1:0]   wr_ptr, rd_ptr;
  reg [PTR_W:0]     count;                       // +1 bit

  wire do_push = push_i && (count < LOG_DEPTH_W);
  wire do_pop  = rd_en && (count != 0);

  wire [ENTRY_W-1:0] entry_new = {ts_cnt, push_addr, push_prot, push_op, push_region};

  always @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      wr_ptr <= {PTR_W{1'b0}};
      rd_ptr <= {PTR_W{1'b0}};
      count  <= {(PTR_W+1){1'b0}};
      ovf_sticky <= 1'b0;
    end else begin
      if (do_push) begin
        entries[wr_ptr] <= entry_new;
        wr_ptr <= (wr_ptr == PTR_W'(LOG_DEPTH-1)) ? {PTR_W{1'b0}} : wr_ptr + 1'b1;
      end
      if (do_pop)
        rd_ptr <= (rd_ptr == PTR_W'(LOG_DEPTH-1)) ? {PTR_W{1'b0}} : rd_ptr + 1'b1;
      case ({do_push, do_pop})
        2'b10: count <= count + 1'b1;
        2'b01: count <= count - 1'b1;
        default: ;
      endcase
      // SEC 4.1 overflow drops NEWEST; stored entries never corrupted
      if (push_i && !do_push) ovf_sticky <= 1'b1;
      else if (ovf_clr)       ovf_sticky <= 1'b0;
    end
  end

  assign rd_data  = entries[rd_ptr];
  assign rd_valid = (count != 0);
  assign cnt_o    = count;
  assign ts_o     = ts_cnt;
  assign irq      = int_en && ((count != 0) || ovf_sticky);
endmodule
