import smtplib
from dotenv import load_dotenv
import os

load_dotenv()


class NotificationManager:
    def __init__(self):
        self.message = ""
        self.list_of_products = []
        self.MY_EMAIL = "dev.dmytro.rudikov@gmail.com"
        self.MY_PASSWORD = os.getenv("EMAIL_PASSWORD")

    def create_msg(self, order_entry):
        products_for_msg = "\n".join(self.list_of_products)
        total_paid = f"\n\nTotal amount: {order_entry.total_amount}USD"
        ending = "\n\nThank you for staying with us!"
        self.message = (f"""Subject:'Shop for the Soul' order #{order_entry.id} receipt!
                       \n\nYou have successfully purchased the following products in our shop:\n\n"""
                        + products_for_msg + total_paid + ending).encode("utf-8")

    def send_msg(self, order_entry):
        with smtplib.SMTP("smtp.gmail.com", 587) as connection:
            connection.starttls()
            connection.login(user=self.MY_EMAIL, password=self.MY_PASSWORD)
            connection.sendmail(
                from_addr=self.MY_EMAIL,
                to_addrs=order_entry.client_email,
                msg=self.message
            )
