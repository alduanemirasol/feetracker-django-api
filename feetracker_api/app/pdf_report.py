from io import BytesIO
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet
from django.http import HttpResponse

def generate_treasurer_report_pdf(summary_data, payment_data, semester, school_year, start_date, end_date, filename="treasurer_report.pdf"):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=20, leftMargin=20, topMargin=20, bottomMargin=20)
    elements = []
    styles = getSampleStyleSheet()

    # Add header info
    header_data = [
        ["Semester:", semester, "School Year:", school_year],
        ["Start Date:", start_date, "End Date:", end_date]
    ]
    table_width = A4[0] - doc.leftMargin - doc.rightMargin
    col_widths_header = [table_width * 0.15, table_width * 0.35, table_width * 0.15, table_width * 0.35]
    header_table = Table(header_data, colWidths=col_widths_header, hAlign='LEFT')
    header_table.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.whitesmoke),
        ('GRID', (0,0), (-1,-1), 0.5, colors.black),
        ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
        ('ALIGN', (0,0), (-1,-1), 'LEFT'),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4)
    ]))
    elements.append(header_table)
    elements.append(Spacer(1, 12))

    # Add summary table
    elements.append(Paragraph("Treasurer Report Summary", styles['Heading2']))
    col_widths_summary = [table_width * 0.5, table_width * 0.5]
    t_summary = Table(summary_data, colWidths=col_widths_summary, hAlign='CENTER')
    t_summary.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('TOPPADDING', (0,0), (-1,-1), 6),
        ('BOTTOMPADDING', (0,0), (-1,-1), 6)
    ]))
    elements.append(t_summary)
    elements.append(Spacer(1, 12))

    # Add payment table
    elements.append(Paragraph("Payment Details", styles['Heading2']))
    num_cols = len(payment_data[0])
    col_widths_payment = [table_width / num_cols] * num_cols
    t_payments = Table(payment_data, colWidths=col_widths_payment, hAlign='CENTER')
    t_payments.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4)
    ]))
    elements.append(t_payments)

    doc.build(elements)
    buffer.seek(0)

    response = HttpResponse(buffer, content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    return response