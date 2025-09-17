from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.colors import HexColor
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from django.http import HttpResponse

def generate_treasurer_report_pdf(summary_data, payment_data, semester, school_year, start_date, end_date, filename="treasurer_report.pdf"):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=20, leftMargin=20, topMargin=20, bottomMargin=20)
    elements = []
    styles = getSampleStyleSheet()

    # Header info
    header_data = [
        ["Semester:", semester, "School Year:", school_year],
        ["Start Date:", start_date, "End Date:", end_date]
    ]
    table_width = A4[0] - doc.leftMargin - doc.rightMargin
    col_widths_header = [table_width * 0.15, table_width * 0.35, table_width * 0.15, table_width * 0.35]

    header_table = Table(header_data, colWidths=col_widths_header, hAlign='LEFT')
    header_table.setStyle(TableStyle([
        # Labels (col 0 and 2)
        ('BACKGROUND', (0,0), (0,-1), HexColor("#1F618D")),
        ('BACKGROUND', (2,0), (2,-1), HexColor("#1F618D")),
        ('TEXTCOLOR', (0,0), (0,-1), colors.white),
        ('TEXTCOLOR', (2,0), (2,-1), colors.white),

        # Values (col 1 and 3)
        ('BACKGROUND', (1,0), (1,-1), colors.white),
        ('BACKGROUND', (3,0), (3,-1), colors.white),
        ('TEXTCOLOR', (1,0), (1,-1), colors.black),
        ('TEXTCOLOR', (3,0), (3,-1), colors.black),

        # Common styles
        ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
        ('FONTSIZE', (0,0), (-1,-1), 10),
        ('GRID', (0,0), (-1,-1), 0.3, HexColor("#B3B6B7")),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('ALIGN', (0,0), (-1,-1), 'CENTER'),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
    ]))

    elements.append(header_table)
    elements.append(Spacer(1, 15))

    # Summary table
    elements.append(Paragraph("Treasurer Report Summary", styles['Heading2']))
    col_widths_summary = [table_width * 0.5, table_width * 0.5]
    t_summary = Table(summary_data, colWidths=col_widths_summary, hAlign='CENTER')

    t_summary.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), HexColor("#1F618D")),  # corporate blue header
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 0.3, HexColor("#B3B6B7")),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [HexColor("#F8F9F9"), HexColor("#EBF5FB")]),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('TOPPADDING', (0,0), (-1,-1), 8),
        ('BOTTOMPADDING', (0,0), (-1,-1), 8),
    ]))
    elements.append(t_summary)
    elements.append(Spacer(1, 15))

    # Payment details table
    elements.append(Paragraph("Payment Details", styles['Heading2']))

    # Keep only Student ID, Payment Date, Amount Paid
    filtered_payment_data = [["Student ID", "Payment Date", "Amount Paid"]]  # header row
    for row in payment_data[1:]:  # skip original header
        amount_value = row[2]
        # Ensure it's formatted with peso sign and commas (if numeric)
        try:
            amount_value = f"P{float(amount_value):,.2f}"
        except:
            amount_value = f"P{amount_value}"
        filtered_payment_data.append([row[0], row[1], amount_value])

    num_cols = len(filtered_payment_data[0])
    col_widths_payment = [table_width / num_cols] * num_cols
    t_payments = Table(filtered_payment_data, colWidths=col_widths_payment, hAlign='CENTER')

    t_payments.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), HexColor("#1F618D")),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 0.3, HexColor("#B3B6B7")),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [HexColor("#F8F9F9"), HexColor("#EBF5FB")]),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6),
    ]))
    elements.append(t_payments)

    # Build PDF
    doc.build(elements)
    buffer.seek(0)

    # Dynamic filename
    filename = f"treasurer_report_{semester}_{school_year}_{start_date}_to_{end_date}.pdf".replace(" ", "_")

    response = HttpResponse(buffer, content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response