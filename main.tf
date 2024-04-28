provider "aws" {
  region = "us-east-1"
  access_key = "..."
  secret_key = "..."
} 

resource "aws_security_group" "ssh" {
  name        = "allow-ssh"
  description = "Allows inbound SSH traffic"

  ingress {
    from_port = 6911
    to_port   = 6911
    protocol  = "tcp"
    cidr_blocks = [
      "0.0.0.0/0"
    ]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [
      "0.0.0.0/0"
    ]
  }
}

resource "tls_private_key" "ubuntu-ssh-key" {
  algorithm   = "RSA"
  rsa_bits    = 4096
}

resource "aws_key_pair" "ubuntu-ssh-key" {
  key_name   = "ubuntu-ssh-key"
  public_key = tls_private_key.ubuntu-ssh-key.public_key_openssh
}

resource "local_file" "ssh_ubuntu_private_key" {
  filename = "${path.module}/ubuntu-ssh-key.pem"
  content  = tls_private_key.ubuntu-ssh-key.private_key_pem
}

resource "tls_private_key" "daniel-ssh-key" {
  algorithm   = "RSA"
  rsa_bits    = 4096
}

resource "aws_key_pair" "daniel-ssh-key" {
  key_name   = "daniel-ssh-key"
  public_key = tls_private_key.daniel-ssh-key.public_key_openssh
}

resource "local_file" "ssh_daniel_private_key" {
  filename = "${path.module}/daniel-ssh-key.pem"
  content  = tls_private_key.daniel-ssh-key.private_key_pem
}

resource "local_file" "ssh_daniel_public_key" {
  filename = "${path.module}/daniel-ssh-key.pub"
  content  = tls_private_key.daniel-ssh-key.public_key_pem
}

resource "aws_instance" "ssh" {
  ami           = "ami-053b0d53c279acc90"
  instance_type = "t2.micro"
  key_name      = aws_key_pair.ubuntu-ssh-key.key_name

  vpc_security_group_ids = [
    aws_security_group.ssh.id
  ]
}

output "public_ip" {
  value = aws_instance.ssh.public_ip
}

resource "null_resource" "init" {

  provisioner "local-exec" {
    command = <<-EOT
      echo "" > commands.test.txt
    EOT
  }
}

resource "null_resource" "save_private_key" {
  triggers = {
    private_keys = "${tls_private_key.ubuntu-ssh-key.private_key_pem}${tls_private_key.daniel-ssh-key.private_key_pem}${aws_instance.ssh.public_ip}"
  }

  provisioner "local-exec" {
    command = <<-EOT
      chmod 600 ubuntu-ssh-key.pem
      chmod 600 daniel-ssh-key.pem
      echo "ssh -o \"IdentitiesOnly=yes\" -i ubuntu-ssh-key.pem -p 22 ubuntu@${aws_instance.ssh.public_ip}" >> commands.test.txt
      echo "sudo useradd -m daniel2" >> commands.test.txt
      echo "sudo -i -u daniel2" >> commands.test.txt
      echo "pwd" >> commands.test.txt
      echo "mkdir /home/daniel2/.ssh" >> commands.test.txt
      echo "chmod 700 /home/daniel2/.ssh" >> commands.test.txt
      echo "touch /home/daniel2/.ssh/authorized_keys" >> commands.test.txt
      echo "chmod 600 /home/daniel2/.ssh/authorized_keys" >> commands.test.txt
      echo "echo \"${aws_key_pair.daniel-ssh-key.public_key}\" >> /home/daniel2/.ssh/authorized_keys"  >> commands.test.txt
      echo "exit" >> commands.test.txt
      echo "exit" >> commands.test.txt
      echo "ssh -o \"IdentitiesOnly=yes\" -i daniel-ssh-key.pem -p 22 daniel2@${aws_instance.ssh.public_ip}" >> commands.test.txt
    EOT
  }
}

/*
terraform init
terraform apply
cat commands.test.txt
commands.test.txt --> contains commands for testing the bastion host
*/
